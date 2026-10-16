use super::*;

pub const BLOCK_COUNT: usize = 4096;
pub const ORIGINAL: &[u8] = b"original file contents";

pub fn image() -> Vec<u8> {
    let mut image = vec![0; BLOCK_COUNT * BLOCK];
    let mut store = |address: usize, bytes: Vec<u8>| {
        image[address * BLOCK..(address + 1) * BLOCK].copy_from_slice(&bytes);
    };
    let w32 = |b: &mut [u8], at, n: u32| put(b, at, &n.to_le_bytes());
    let w64 = |b: &mut [u8], at, n: u64| put(b, at, &n.to_le_bytes());
    let physical = 0x4000_0000;
    let ephemeral = 0x8000_0000;
    let tree = |address, subtype, fixed, flags, records: &[Entry]| {
        let mut b = btree_node(address, true, true, 0, fixed, flags, false, records);
        w32(&mut b, 24, physical | 2);
        w32(&mut b, 28, subtype);
        seal(b)
    };
    let mut data = vec![0; BLOCK];
    data[..ORIGINAL.len()].copy_from_slice(ORIGINAL);
    store(61, data);
    let mut bitmap = vec![0; BLOCK];
    bitmap[..9].fill(0xff);
    store(63, bitmap);
    let mut cib = object(62, 1, physical | 7);
    w32(&mut cib, 36, 1);
    w64(&mut cib, 40, 1);
    w32(&mut cib, 56, BLOCK_COUNT as u32);
    w32(&mut cib, 60, (BLOCK_COUNT - 72) as u32);
    w64(&mut cib, 64, 63);
    store(62, seal(cib));
    let mut reference = (1_u64 | (1_u64 << 60)).to_le_bytes().to_vec();
    reference.extend_from_slice(&16_u64.to_le_bytes());
    reference.extend_from_slice(&1_u32.to_le_bytes());
    store(
        64,
        tree(64, 15, None, 0x10 | 0x40, &[(fs_key(61, 1), reference)]),
    );
    store(65, tree(65, 16, None, 0x10, &[]));
    let mut root = inode_entry(2, 2, 0o040755, 0);
    root.1.truncate(92);
    w64(&mut root.1, 0, 1);
    let mut file = inode_entry(16, 16, 0o100644, ORIGINAL.len() as u64);
    put(&mut file.1, 94, &44_u16.to_le_bytes());
    file.1[97] = 0x20;
    w64(&mut file.1, 108, BLOCK as u64);
    let mut root_name = drec_entry_bytes(1, b"root", 2, false);
    put(&mut root_name.1, 16, &4_u16.to_le_bytes());
    let records = [
        root_name,
        root,
        drec_entry_bytes(2, b"existing", 16, false),
        file,
        (fs_key(16, 6), 1_u32.to_le_bytes().to_vec()),
        extent_entry(16, BLOCK as u64, 61),
    ];
    let mut fs = tree(1027, 14, None, 0x40, &records);
    w32(&mut fs, 24, 2);
    store(66, seal(fs));
    for (address, root_address, entries) in [
        (67, 68, vec![omap_entry(1027, 1, 66, 0)]),
        (70, 71, vec![omap_entry(1026, 1, 69, 0)]),
    ] {
        let mut omap = object(address, 1, physical | 11);
        w32(&mut omap, 40, physical | 2);
        w64(&mut omap, 48, root_address);
        store(address as usize, seal(omap));
        store(
            root_address as usize,
            tree(root_address, 11, Some((16, 16)), 0x10, &entries),
        );
    }
    let mut volume = object(1026, 1, 13);
    put(&mut volume, 32, b"APSB");
    w64(&mut volume, 88, 8);
    w32(&mut volume, 116, 2);
    w32(&mut volume, 120, physical | 2);
    w32(&mut volume, 124, physical | 2);
    for (at, value) in [
        (128, 67),
        (136, 1027),
        (144, 64),
        (152, 65),
        (176, 17),
        (184, 1),
        (224, 8),
        (264, 1),
    ] {
        w64(&mut volume, at, value);
    }
    put(&mut volume, 704, b"write-test");
    store(69, seal(volume));
    let mut sm = object(1024, 1, ephemeral | 5);
    for (at, value) in [
        (32, BLOCK as u32),
        (36, 32768),
        (40, 126),
        (44, 507),
        (64, 1),
        (80, 2528),
        (336, 1),
        (340, 2520),
    ] {
        w32(&mut sm, at, value);
    }
    for (at, value) in [
        (48, BLOCK_COUNT as u64),
        (56, 1),
        (72, (BLOCK_COUNT - 72) as u64),
        (2528, 62),
    ] {
        w64(&mut sm, at, value);
    }
    store(9, seal(sm));
    let mut reaper = object(1025, 1, ephemeral | 17);
    w64(&mut reaper, 32, 1);
    w64(&mut reaper, 40, 1);
    w32(&mut reaper, 64, 1);
    w32(&mut reaper, 108, (BLOCK - 112) as u32);
    store(10, seal(reaper));
    let mut map = object(1, 1, physical | 12);
    w32(&mut map, 32, 1);
    w32(&mut map, 36, 2);
    for (index, kind, oid, address) in [(0, 5, 1024, 9), (1, 17, 1025, 10)] {
        let at = 40 + index * 40;
        w32(&mut map, at, ephemeral | kind);
        w32(&mut map, at + 8, BLOCK as u32);
        w64(&mut map, at + 24, oid);
        w64(&mut map, at + 32, address);
    }
    store(1, seal(map));
    let mut nx = object(1, 1, ephemeral | 1);
    put(&mut nx, 32, b"NXSB");
    for (at, value) in [
        (36, BLOCK as u32),
        (104, 8),
        (108, 52),
        (128, 2),
        (132, 2),
        (140, 2),
        (148, 2),
        (180, 1),
    ] {
        w32(&mut nx, at, value);
    }
    for (at, value) in [
        (40, BLOCK_COUNT as u64),
        (64, 2),
        (88, 1028),
        (96, 2),
        (112, 1),
        (120, 9),
        (152, 1024),
        (160, 70),
        (168, 1025),
        (184, 1026),
    ] {
        w64(&mut nx, at, value);
    }
    let nx = seal(nx);
    store(2, nx.clone());
    store(0, nx);
    image
}
