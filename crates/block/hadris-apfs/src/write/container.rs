io_transform! {
use super::Container;
use super::super::storage::BlockDevice;
use alloc::{collections::BTreeSet, vec, vec::Vec};
use crate::types::{ContainerSuperblock, VolumeSuperblock, ObjectMapBlock, ObjectMapValue, OwnedEntry, VirtualObjectMap, FileExtentRecord};
use crate::types::{le_u32,le_u64};
use crate::types::checksum::verify_object;
use crate::write::{self, Allocation, AllocationChunk, Records, WriteOperation, BLOCK, extent_ref,object,omap,omap_entry,seal,w32,w64,unsupported};
use hadris_fs::{Error,ErrorKind,FsResult};
use hadris_storage::BlockIndex;

struct State {
    nx:Vec<u8>, volume:Vec<u8>, sm:Vec<u8>, reaper:Vec<u8>,
    allocation:Allocation, records:Records, cibs:Vec<(u64,Vec<u8>)>,
    extents:Vec<FileExtentRecord>, desc_index:u32, data_index:u32,
}
fn write_error<E>(e:crate::ApfsError)->Error<E>{match e {crate::ApfsError::InvalidValue("APFS write space exhausted")=>Error::new(ErrorKind::NoSpace,"APFS write space exhausted (old allocations are retained)"),other=>other.into()}}
fn extent_entries(extents:&[FileExtentRecord])->Vec<OwnedEntry>{let mut result:Vec<_>=extents.iter().map(|e|extent_ref(e.physical_block,e.length/BLOCK as u64,e.id)).collect();result.sort_by_key(|e|le_u64(&e.key,0).unwrap_or(0)&0x0fff_ffff_ffff_ffff);result}
fn free_ring_pair<E>(count:u32,start:u32,len:u32,next:u32)->FsResult<u32,E>{
    if count<4 || start>=count || len==0 || len>count-2 || next>=count{return Err(unsupported("APFS checkpoint ring geometry for writes"));}
    for step in 0..count{let candidate=(u64::from(next)+u64::from(step))%u64::from(count);let c=candidate as u32;let busy=|idx:u32|(u64::from(idx)+u64::from(count)-u64::from(start))%u64::from(count)<u64::from(len);if !busy(c)&&!busy((c+1)%count){return Ok(c);}}
    Err(unsupported("APFS checkpoint ring has no inactive pair"))
}
fn zero(data:&[u8])->bool{data.iter().all(|b|*b==0)}

impl<D:BlockDevice> Container<D> {
    pub(crate) async fn validate_write(&mut self,checkpoint:&ContainerSuperblock,volume:&VolumeSuperblock)->FsResult<(),D::Error>{self.load_write(checkpoint,volume).await.map(drop)}
    pub(crate) async fn flush_write(&mut self)->FsResult<(),D::Error>{if self.write_in_flight{return Err(Error::new(ErrorKind::ReadOnly,"APFS writer requires reopening after interrupted transaction"));}self.device.flush().await}

    async fn checked_object(&mut self,block:u64,oid:u64,kind:u32,xid:u64,live:&mut BTreeSet<u64>)->FsResult<Vec<u8>,D::Error>{
        if !live.insert(block){return Err(Error::new(ErrorKind::Corrupt,"APFS metadata block alias"));}
        let b=self.read_apfs_block_vec(block).await?;verify_object(&b)?;
        let h=crate::types::ObjectHeader::parse(&b)?;
        if h.identifier!=oid || h.object_type!=kind || h.transaction_identifier>xid{return Err(unsupported("APFS write object storage type or transaction"));}Ok(b)
    }
    async fn write_tree(&mut self,root:u64,subtype:u32,map:Option<&VirtualObjectMap>,xid:u64,live:&mut BTreeSet<u64>)->FsResult<Vec<OwnedEntry>,D::Error>{
        let physical=map.is_none();let root_block=if let Some(map)=map{let value=map.resolve(root).ok_or(crate::ApfsError::InvalidValue("APFS write root mapping"))?;if value.flags!=0 || value.size!=BLOCK as u32{return Err(unsupported("APFS write object map flags"));}value.address}else{root};
        let root_data=self.checked_object(root_block,root,if physical{0x4000_0002}else{2},xid,live).await?;
        let node=crate::types::OwnedBTreeNode::parse(root_data)?;let info=node.tree_info()?;
        if info.fixed.flags & !0x50!=0 || (info.fixed.flags & 0x10 !=0)!=physical || info.fixed.node_size!=BLOCK as u32 || node.node()?.object.subtype!=subtype{return Err(unsupported("APFS write B-tree flags or subtype"));}
        let header=node.node()?;
        let fixed=subtype==11;
        if header.flags & !7!=0 || (header.flags&4!=0)!=fixed || (header.flags&2!=0)!=(header.level==0) || (fixed&&(info.fixed.key_size!=16||info.fixed.value_size!=16)) || (!fixed&&(info.fixed.key_size!=0||info.fixed.value_size!=0)){return Err(unsupported("APFS write B-tree node layout"));}
        let mut stack=vec![node];let mut entries=Vec::new();
        while let Some(node)=stack.pop(){
            let records=node.owned_entries(Some(info))?;
            if node.is_leaf()?{entries.extend(records);continue;}
            if records.is_empty(){return Err(ErrorKind::Corrupt.into());}
            for e in records.into_iter().rev(){
                if e.value.len()!=8{return Err(unsupported("APFS hashed B-tree child"));}
                let oid=le_u64(&e.value,0)?;
                let block=if let Some(map)=map{let value=map.resolve(oid).ok_or(crate::ApfsError::InvalidValue("APFS write child mapping"))?;if value.flags!=0 || value.size!=BLOCK as u32{return Err(unsupported("APFS write child map flags"));}value.address}else{oid};
                let b=self.checked_object(block,oid,if physical{0x4000_0003}else{3},xid,live).await?;
                let child=crate::types::OwnedBTreeNode::parse(b)?;
                let header=child.node()?;
                if header.object.subtype!=subtype || node.node()?.level.checked_sub(1)!=Some(header.level) || header.flags&!6!=0 || (header.flags&4!=0)!=fixed || (header.flags&2!=0)!=(header.level==0){return Err(ErrorKind::Corrupt.into());}
                stack.push(child);
            }
        }
        Ok(entries)
    }
    async fn write_map(&mut self,block:u64,xid:u64,live:&mut BTreeSet<u64>)->FsResult<(ObjectMapBlock,Vec<OwnedEntry>),D::Error>{
        let b=self.checked_object(block,block,0x4000_000b,xid,live).await?;let map=ObjectMapBlock::parse(&b)?;
        if map.flags & !1 !=0 || map.snapshot_count!=0 || map.tree_type!=0x4000_0002 || map.snapshot_tree_oid!=0 || map.most_recent_snapshot_identifier!=0 || map.pending_revert_minimum_identifier!=0 || map.pending_revert_maximum_identifier!=0{return Err(unsupported("APFS write object map snapshots or flags"));}
        let entries=self.write_tree(map.tree_oid,11,None,xid,live).await?;
        let mut previous=None;
        for e in &entries {let k=(le_u64(&e.key,0)?,le_u64(&e.key,8)?);let v=ObjectMapValue::parse(&e.value)?;if e.key.len()!=16 || e.value.len()!=16 || v.flags!=0 || v.size!=BLOCK as u32 || k.1>xid || previous.is_some_and(|p|p>=k){return Err(unsupported("APFS write object map records"));}previous=Some(k);}
        Ok((map,entries))
    }
    async fn load_write(&mut self,nx:&ContainerSuperblock,volume:&VolumeSuperblock)->FsResult<State,D::Error>{
        if self.write_in_flight{return Err(Error::new(ErrorKind::ReadOnly,"APFS writer requires reopening after interrupted transaction"));}
        if !self.device.writable(){return Err(ErrorKind::ReadOnly.into());}
        if self.device.physical_block_size().get()>BLOCK as u32 || BLOCK as u32%self.device.physical_block_size().get()!=0 || self.device.disk_offset()%u64::from(self.device.physical_block_size().get())!=0{return Err(unsupported("APFS write physical block alignment"));}
        if self.latest_superblock().await?!=*nx{return Err(Error::new(ErrorKind::Busy,"APFS checkpoint changed since mount"));}
        if nx.object.object_type!=0x8000_0001 || nx.object.identifier!=1 || nx.object.transaction_identifier==0 || nx.next_transaction_identifier<=nx.object.transaction_identifier{return Err(unsupported("APFS write container object or transaction identifiers"));}
        if nx.block_size!=BLOCK as u32 || nx.compatible_features!=0 || nx.readonly_compatible_features!=0 || nx.incompatible_features!=2 || nx.volumes().count()!=1 || nx.volumes().next()!=Some(volume.object.identifier) || nx.keylocker_blocks!=0 || nx.flags & !4 !=0{return Err(unsupported("APFS write container features or multiple volumes"));}
        if volume.flags!=1 || volume.optional_features!=0 || volume.readonly_compatible_features!=0 || volume.incompatible_features & !8 !=0 || volume.number_snapshots!=0 || volume.fext_tree_oid!=0{return Err(unsupported("APFS write encrypted, sealed, snapshot or case-insensitive volume"));}
        let dc=nx.checkpoint_descriptor_area_block_count;let db=nx.checkpoint_data_area_block_count;let base=nx.checkpoint_descriptor_area_block;let data=nx.checkpoint_data_area_block;
        if dc & (1<<31)!=0 || db & (1<<31)!=0 || base==0 || data==0 || base.checked_add(u64::from(dc)).is_none_or(|e|e>nx.block_count) || data.checked_add(u64::from(db)).is_none_or(|e|e>nx.block_count) || (base<data+u64::from(db)&&data<base+u64::from(dc)){return Err(unsupported("APFS write checkpoint areas"));}
        let mut raw=None;
        for idx in 0..dc {let b=self.read_apfs_block_vec(base+u64::from(idx)).await?;if verify_object(&b).is_ok() && ContainerSuperblock::parse(&b).is_ok_and(|s|s==*nx){raw=Some(b);break;}}
        let raw=if let Some(b)=raw{b}else{let b=self.read_apfs_block_vec(0).await?;verify_object(&b)?;if ContainerSuperblock::parse(&b)?!=*nx{return Err(ErrorKind::Corrupt.into());}b};
        if !zero(&raw[1232..1264]) || !zero(&raw[1264+8..1296]) || !zero(&raw[1344..1384]){return Err(unsupported("APFS write container extension objects"));}
        let desc_index=free_ring_pair::<D::Error>(dc,nx.checkpoint_descriptor_area_start_index,nx.checkpoint_descriptor_area_length,le_u32(&raw,128)?)?;
        let current_data=le_u32(&raw,144)?;let current_len=le_u32(&raw,148)?;let data_index=free_ring_pair::<D::Error>(db,current_data,current_len,le_u32(&raw,132)?)?;
        let mut maps=self.checkpoint_map_blocks(nx).await?;
        if maps.len()!=1 || maps[0].object.object_type!=0x4000_000c || maps[0].object.transaction_identifier!=nx.object.transaction_identifier || maps[0].flags!=1{return Err(unsupported("APFS write checkpoint map chain"));}
        let mappings=maps.pop().ok_or(crate::ApfsError::InvalidValue("APFS write checkpoint map"))?.mappings;
        if mappings.len()!=2 || mappings.iter().any(|m|m.size!=BLOCK as u32 || m.filesystem_identifier!=0 || m.object_subtype!=0 || m.address<data || m.address>=data+u64::from(db) || (m.address-data+u64::from(db)-u64::from(current_data))%u64::from(db)>=u64::from(current_len)){return Err(unsupported("APFS write ephemeral checkpoint objects"));}
        let sm_mapping=mappings.iter().find(|m|m.container_identifier==nx.space_manager_oid&&m.object_type==0x8000_0005).ok_or_else(||unsupported("APFS write spaceman checkpoint mapping"))?;
        let reap_mapping=mappings.iter().find(|m|m.container_identifier==nx.reaper_oid&&m.object_type==0x8000_0011).ok_or_else(||unsupported("APFS write reaper checkpoint mapping"))?;
        let mut live=BTreeSet::new();
        let sm=self.checked_object(sm_mapping.address,nx.space_manager_oid,0x8000_0005,nx.object.transaction_identifier,&mut live).await?;
        let reaper=self.checked_object(reap_mapping.address,nx.reaper_oid,0x8000_0011,nx.object.transaction_identifier,&mut live).await?;
        if !zero(&sm[96..336]) || !zero(&sm[344..2520]) || le_u32(&sm,336)?!=1 || le_u32(&sm,340)?!=2520 || le_u32(&sm,32)?!=BLOCK as u32 || le_u32(&sm,36)?!=BLOCK as u32*8 || le_u32(&sm,40)?!=(BLOCK as u32-40)/32 || le_u32(&sm,44)?!=(BLOCK as u32-40)/8{return Err(unsupported("APFS write spaceman internal pool, free queues or allocation zones"));}
        if !zero(&reaper[48..64]) || !zero(&reaper[68..108]) || !zero(&reaper[112..]) || le_u64(&reaper,32)?!=le_u64(&reaper,40)? || le_u32(&reaper,64)? & !1 !=0{return Err(unsupported("APFS write pending reaper work"));}
        let summary=crate::types::SpaceManagerSummary::parse(&sm)?;if summary.main_device.block_count!=nx.block_count || summary.main_device.chunk_info_address_block_count!=0 || summary.main_device.address_offset<2520{return Err(unsupported("APFS write spaceman device layout"));}
        let mut cibs=Vec::new();let mut chunks=Vec::new();let mut start=0u64;let mut free=0u64;
        for address in summary.main_device_chunk_info_block_addresses(&sm)? {let b=self.checked_object(address,address,0x4000_0007,nx.object.transaction_identifier,&mut live).await?;if le_u32(&b,32)?!=cibs.len() as u32{return Err(ErrorKind::Corrupt.into());}for ci in crate::types::parse_chunk_info_block(&b)?{if ci.address!=start || ci.block_count==0 || ci.block_count>BLOCK as u32*8 || ci.address.checked_add(u64::from(ci.block_count)).is_none_or(|end|end>nx.block_count){return Err(ErrorKind::Corrupt.into());}let bitmap=if ci.bitmap_address==0{if ci.free_count!=ci.block_count{return Err(ErrorKind::Corrupt.into());}vec![0;BLOCK]}else{if !live.insert(ci.bitmap_address){return Err(ErrorKind::Corrupt.into());}self.read_apfs_block_vec(ci.bitmap_address).await?};let actual=(0..ci.block_count as usize).filter(|bit|bitmap[bit/8]&(1<<(bit%8))==0).count()as u32;if actual!=ci.free_count{return Err(Error::new(ErrorKind::Corrupt,"APFS allocation bitmap free count"));}start+=u64::from(ci.block_count);free+=u64::from(ci.free_count);chunks.push(AllocationChunk{start:ci.address,count:ci.block_count,bitmap,new_bitmap:0});}cibs.push((address,b));}
        if start!=nx.block_count || free!=summary.main_device.free_count || le_u64(&sm,56)?!=chunks.len() as u64{return Err(ErrorKind::Corrupt.into());}
        let allocation=Allocation{chunks,free,next_oid:nx.next_object_identifier,used:0,avoid:[nx.space_manager_oid,nx.reaper_oid],cursor:0};
        let (_,container_entries)=self.write_map(nx.object_map_oid,nx.object.transaction_identifier,&mut live).await?;
        let mut value=None;for e in &container_entries{if le_u64(&e.key,0)?!=volume.object.identifier{return Err(unsupported("APFS write container virtual objects"));}value=Some(ObjectMapValue::parse(&e.value)?);}
        let v=value.ok_or(crate::ApfsError::InvalidValue("APFS write volume mapping"))?;
        let vb=self.checked_object(v.address,volume.object.identifier,13,nx.object.transaction_identifier,&mut live).await?;
        if VolumeSuperblock::parse(&vb)?!=*volume{return Err(ErrorKind::Busy.into());}
        if !zero(&vb[72..88]) || !zero(&vb[96..116]) || !zero(&vb[160..176]) || le_u64(&vb,208)?!=0 || !zero(&vb[964..1064]) || le_u32(&vb,116)?!=2 || le_u32(&vb,120)?!=0x4000_0002 || le_u32(&vb,124)?!=0x4000_0002{return Err(unsupported("APFS write volume extensions, roles or reserves"));}
        let (_,ventries)=self.write_map(volume.object_map_oid,volume.object.transaction_identifier,&mut live).await?;
        let values:Vec<_>=ventries.iter().map(|e|Ok((crate::types::ObjectMapKey{oid:le_u64(&e.key,0)?,xid:le_u64(&e.key,8)?},ObjectMapValue::parse(&e.value)?))).collect::<crate::Result<_>>()?;
        let virtual_map=VirtualObjectMap::new(&values,volume.object.transaction_identifier);
        if nx.next_object_identifier<=values.iter().map(|(k,_)|k.oid).max().unwrap_or(0){return Err(ErrorKind::Corrupt.into());}
        let entries=self.write_tree(volume.root_tree_oid,14,Some(&virtual_map),volume.object.transaction_identifier,&mut live).await?;
        let records=Records{entries,next_id:le_u64(&vb,176)?,hashed:volume.directory_key_layout()==crate::types::filesystem::DirectoryKeyLayout::Hashed};
        let extents=records.validate::<D::Error>(volume,nx.block_count)?;
        let references=self.write_tree(volume.extent_reference_tree_oid,15,None,volume.object.transaction_identifier,&mut live).await?;let expected=extent_entries(&extents);
        if references.len()!=expected.len() || references.iter().zip(&expected).any(|(a,b)|a.key!=b.key || a.value!=b.value){return Err(unsupported("APFS write extent references or clones"));}
        if !self.write_tree(volume.snapshot_metadata_tree_oid,16,None,volume.object.transaction_identifier,&mut live).await?.is_empty(){return Err(unsupported("APFS write snapshot metadata"));}
        for &block in &live{if block!=sm_mapping.address&&block!=reap_mapping.address&&(block==0||(base..base+u64::from(dc)).contains(&block)||(data..data+u64::from(db)).contains(&block)){return Err(Error::new(ErrorKind::Corrupt,"APFS metadata overlaps checkpoint rings"));}}
        for block in core::iter::once(0).chain(base..base+u64::from(dc)).chain(data..data+u64::from(db)).chain(live.iter().copied()){if !allocation.allocated(block){return Err(Error::new(ErrorKind::Corrupt,"APFS live metadata marked free"));}}
        for e in &extents{for block in e.physical_block..e.physical_block+e.length/BLOCK as u64{if !allocation.allocated(block)||live.contains(&block)||block==0||(base..base+u64::from(dc)).contains(&block)||(data..data+u64::from(db)).contains(&block){return Err(Error::new(ErrorKind::Corrupt,"APFS file extent allocation overlaps metadata"));}}}
        Ok(State{nx:raw,volume:vb,sm,reaper,allocation,records,cibs,extents,desc_index,data_index})
    }

    async fn stage_file(&mut self,state:&mut State,node:u64,new_len:u64,write:Option<(u64,&[u8])>,writes:&mut Vec<(u64,Vec<u8>)>)->FsResult<(),D::Error>{
        let inode=state.records.inode::<D::Error>(node)?;
        if inode.mode & 0o170000 !=0o100000{return Err(if inode.mode & 0o170000==0o040000{ErrorKind::IsADirectory}else{ErrorKind::Unsupported}.into());}
        if new_len>0x00ff_ffff_ffff_ffff{return Err(ErrorKind::FileTooLarge.into());}
        let old_len=inode.data_stream_size.unwrap_or(0);
        let count=new_len.div_ceil(BLOCK as u64);
        if count>self.info.superblock.block_count{return Err(ErrorKind::NoSpace.into());}
        let first=state.extents.partition_point(|e|e.id<node);
        let end=state.extents.partition_point(|e|e.id<=node);
        let old=&state.extents[first..end];
        let mut cursor=0usize;
        let mut next=Vec::<FileExtentRecord>::new();
        let mut logical=0u64;
        while logical<count*BLOCK as u64{
            while cursor<old.len()&&old[cursor].logical_address+old[cursor].length<=logical{cursor+=1;}
            let source=old.get(cursor).filter(|e|logical>=e.logical_address&&logical<e.logical_address+e.length);
            let source_block=source.map(|e|e.physical_block+(logical-e.logical_address)/BLOCK as u64);
            let touched=write.is_some_and(|(offset,data)|offset<logical+BLOCK as u64&&offset+data.len()as u64>logical);
            let tail_changed=new_len!=old_len&&(logical+BLOCK as u64>old_len||(new_len<old_len&&logical+BLOCK as u64>new_len));
            let (physical,length)=if touched||tail_changed||source.is_none(){
                let physical=state.allocation.allocate().map_err(write_error)?;
                let mut b=if let Some(src)=source_block{self.read_apfs_block_vec(src).await?}else{vec![0;BLOCK]};
                if old_len<logical+BLOCK as u64{b[old_len.saturating_sub(logical)as usize..].fill(0);}
                if let Some((offset,data))=write{
                    let start=offset.max(logical);let end=(offset+data.len()as u64).min(logical+BLOCK as u64);
                    if start<end{b[(start-logical)as usize..(end-logical)as usize].copy_from_slice(&data[(start-offset)as usize..(end-offset)as usize]);}
                }
                if new_len<logical+BLOCK as u64{b[(new_len-logical)as usize..].fill(0);}
                writes.push((physical,b));
                (physical,BLOCK as u64)
            }else{
                let source=source.ok_or(crate::ApfsError::InvalidValue("APFS file extent gap"))?;
                let mut stop=(source.logical_address+source.length).min(count*BLOCK as u64);
                if let Some((offset,_))=write{let boundary=offset/BLOCK as u64*BLOCK as u64;if boundary>logical{stop=stop.min(boundary);}}
                if new_len!=old_len{let boundary=old_len.min(new_len)/BLOCK as u64*BLOCK as u64;if boundary>logical{stop=stop.min(boundary);}}
                (source_block.ok_or(crate::ApfsError::InvalidValue("APFS file extent gap"))?,stop-logical)
            };
            if let Some(last)=next.last_mut()&&last.physical_block+last.length/BLOCK as u64==physical{last.length+=length;}else{
                next.push(FileExtentRecord{id:node,logical_address:logical,length,flags:0,physical_block:physical,cryptography_id:0});
            }
            logical+=length;
        }
        state.records.replace_extents::<D::Error>(node,new_len,&next)?;
        state.extents.retain(|e|e.id!=node);state.extents.extend(next);
        Ok(())
    }

    pub(crate) async fn mutate(&mut self,checkpoint:&mut ContainerSuperblock,volume:&mut VolumeSuperblock,operation:WriteOperation<'_>)->FsResult<Option<u64>,D::Error>{
        let mut state=self.load_write(checkpoint,volume).await?;let mut writes=Vec::new();
        let created=match operation{
            WriteOperation::Write{node,offset,data}=>{if data.is_empty(){return Ok(None);}let old=state.records.inode::<D::Error>(node)?.data_stream_size.unwrap_or(0);let end=offset.checked_add(data.len()as u64).ok_or_else(||Error::from(ErrorKind::FileTooLarge))?;self.stage_file(&mut state,node,old.max(end),Some((offset,data)),&mut writes).await?;None}
            WriteOperation::Truncate{node,len}=>{let old=state.records.inode::<D::Error>(node)?;if old.mode & 0o170000 !=0o100000{return Err(if old.mode & 0o170000==0o040000{ErrorKind::IsADirectory}else{ErrorKind::Unsupported}.into());}
                if old.data_stream_size.unwrap_or(0)==len{return Ok(None);}self.stage_file(&mut state,node,len,None,&mut writes).await?;None}
            other=>state.records.metadata::<D::Error>(volume,other)?,
        };
        state.extents=state.records.validate::<D::Error>(volume,checkpoint.block_count)?;
        let xid=checkpoint.next_transaction_identifier.max(checkpoint.object.transaction_identifier.checked_add(1).ok_or(crate::ApfsError::AddressOverflow)?);let next_xid=xid.checked_add(1).ok_or(crate::ApfsError::AddressOverflow)?;
        let fst=write::btree::build(&state.records.entries,xid,14,false,None,&mut||state.allocation.node(false)).map_err(write_error)?;
        writes.extend(fst.nodes);let root_oid=fst.root_oid;
        let refs=extent_entries(&state.extents);let ext=write::btree::build(&refs,xid,15,true,None,&mut||state.allocation.node(true)).map_err(write_error)?;writes.extend(ext.nodes);
        let vmap:Vec<_>=fst.mappings.into_iter().map(|(oid,block)|omap_entry(oid,block,xid)).collect();
        let vm_tree=write::btree::build(&vmap,xid,11,true,Some((16,16)),&mut||state.allocation.node(true)).map_err(write_error)?;writes.extend(vm_tree.nodes);
        let vm=state.allocation.allocate().map_err(write_error)?;writes.push((vm,omap(vm,vm_tree.root_block,xid,0)));
        let vb=state.allocation.allocate().map_err(write_error)?;
        w64(&mut state.volume,16,xid);w64(&mut state.volume,128,vm);w64(&mut state.volume,136,root_oid);w64(&mut state.volume,144,ext.root_block);w64(&mut state.volume,176,state.records.next_id);
        let mut files=0u64;let mut directories=0u64;let mut symlinks=0u64;
        for e in &state.records.entries{if crate::types::FileSystemKey::parse(&e.key)?.record_type==3{let inode=crate::types::InodeRecord::parse(&e.key,&e.value)?;match inode.mode&0o170000{0o100000=>files+=1,0o040000 if inode.id>3=>directories+=1,0o120000=>symlinks+=1,_=>{}}}}
        let added=state.allocation.used;let allocated=volume.allocated_block_count.checked_add(added).ok_or(crate::ApfsError::AddressOverflow)?;
        w64(&mut state.volume,88,allocated);w64(&mut state.volume,184,files);w64(&mut state.volume,192,directories);w64(&mut state.volume,200,symlinks);let total=le_u64(&state.volume,224)?.checked_add(added).ok_or(crate::ApfsError::AddressOverflow)?;w64(&mut state.volume,224,total);seal(&mut state.volume);
        let new_volume=VolumeSuperblock::parse(&state.volume)?;writes.push((vb,state.volume));
        let cm_tree=write::btree::build(&[omap_entry(volume.object.identifier,vb,xid)],xid,11,true,Some((16,16)),&mut||state.allocation.node(true)).map_err(write_error)?;writes.extend(cm_tree.nodes);let cm=state.allocation.allocate().map_err(write_error)?;writes.push((cm,omap(cm,cm_tree.root_block,xid,1)));
        for idx in 0..state.allocation.chunks.len(){let block=state.allocation.allocate().map_err(write_error)?;state.allocation.chunks[idx].new_bitmap=block;}
        let mut new_cibs=Vec::with_capacity(state.cibs.len());for _ in &state.cibs{new_cibs.push(state.allocation.allocate().map_err(write_error)?);}
        let mut chunk=0usize;
        for ((_,mut bytes),block) in state.cibs.into_iter().zip(&new_cibs){w64(&mut bytes,8,*block);w64(&mut bytes,16,xid);let count=le_u32(&bytes,36)? as usize;for ci in 0..count{let c=state.allocation.chunks.get(chunk).ok_or(crate::ApfsError::InputTooSmall)?;let free=(0..c.count as usize).filter(|bit|c.bitmap[bit/8]&(1<<(bit%8))==0).count();let at=40+ci*32;w64(&mut bytes,at,xid);w32(&mut bytes,at+20,free as u32);w64(&mut bytes,at+24,c.new_bitmap);chunk+=1;}seal(&mut bytes);writes.push((*block,bytes));}
        for c in state.allocation.chunks{writes.push((c.new_bitmap,c.bitmap));}
        let addr=le_u32(&state.sm,80)?as usize;for (idx,block)in new_cibs.iter().enumerate(){w64(&mut state.sm,addr+idx*8,*block);}w64(&mut state.sm,16,xid);w64(&mut state.sm,72,state.allocation.free);seal(&mut state.sm);w64(&mut state.reaper,16,xid);seal(&mut state.reaper);
        let dc=checkpoint.checkpoint_descriptor_area_block_count;let db=checkpoint.checkpoint_data_area_block_count;let desc=checkpoint.checkpoint_descriptor_area_block+u64::from(state.desc_index);let nx_block=checkpoint.checkpoint_descriptor_area_block+u64::from((state.desc_index+1)%dc);let sm_block=checkpoint.checkpoint_data_area_block+u64::from(state.data_index);let reap_block=checkpoint.checkpoint_data_area_block+u64::from((state.data_index+1)%db);
        writes.push((sm_block,state.sm));writes.push((reap_block,state.reaper));
        let mut map=object(desc,xid,0x4000_000c,0);w32(&mut map,32,1);w32(&mut map,36,2);for(idx,(kind,oid,block))in[(0x8000_0005,checkpoint.space_manager_oid,sm_block),(0x8000_0011,checkpoint.reaper_oid,reap_block)].into_iter().enumerate(){let at=40+idx*40;w32(&mut map,at,kind);w32(&mut map,at+8,BLOCK as u32);w64(&mut map,at+24,oid);w64(&mut map,at+32,block);}seal(&mut map);
        w64(&mut state.nx,16,xid);w64(&mut state.nx,88,state.allocation.next_oid);w64(&mut state.nx,96,next_xid);w32(&mut state.nx,128,(state.desc_index+2)%dc);w32(&mut state.nx,132,(state.data_index+2)%db);w32(&mut state.nx,136,state.desc_index);w32(&mut state.nx,140,2);w32(&mut state.nx,144,state.data_index);w32(&mut state.nx,148,2);w64(&mut state.nx,160,cm);seal(&mut state.nx);let new_checkpoint=ContainerSuperblock::parse(&state.nx)?;
        // Only inactive ring slots and bitmap-free blocks are touched before publication.
        self.write_in_flight=true;
        for (block,bytes)in writes{self.write_apfs(block,&bytes).await?;}
        self.write_apfs(desc,&map).await?;self.device.flush().await?;
        self.write_apfs(nx_block,&state.nx).await?;self.device.flush().await?;
        *checkpoint=new_checkpoint;*volume=new_volume;self.info.superblock=checkpoint.clone();self.zero_error=None;self.trees=None;self.write_in_flight=false;Ok(created)
    }
    async fn write_apfs(&mut self,block:u64,bytes:&[u8])->FsResult<(),D::Error>{if bytes.len()!=BLOCK || block>=self.info.superblock.block_count{return Err(ErrorKind::InvalidInput.into());}let factor=u64::from(self.info.superblock.block_size/self.device_block_size);let sector=block.checked_mul(factor).ok_or(crate::ApfsError::AddressOverflow)?;self.device.write_blocks(BlockIndex::new(sector),bytes).await}
}
}
