const fs = require('fs');
const crypto = require('crypto');

// Function to inspect a binary file and determine attributes inspired by techniques in "Practical Binary Analysis" by Dennis Andriesse.
// This includes file type detection, header parsing (focusing on ELF, with basic support for PE and Mach-O), string extraction, entropy calculation, and basic section/symbol listing.
// Outputs a JSON object with structured data following a universal schema for use in Max/MSP or similar.
// Assumes little-endian where applicable; limited big-endian support.
// Structures are normalized: headers as name-value pairs, tables as arrays of entries, segments/sections as grouped data pointers.

function inspectBinary(filePath) {
  try {
    const buffer = fs.readFileSync(filePath);
    const size = buffer.length;

    const result = {
      metadata: {
        filePath: filePath,
        size: size,
        hash: crypto.createHash('sha256').update(buffer).digest('hex'),
        magic: buffer.slice(0, 4).toString('hex').toUpperCase(),
        fileType: 'Unknown',
        entropy: 0,
        strings: []
      },
      structures: {
        headers: [], // Array of {name: string, value: any, type: string, offset: number}
        tables: [],  // Array of {name: string, entries: array of objects}
        segments: [], // Array of {name: string, offset: number, size: number, type: string}
        groups: {    // Categorized groupings (logical, mechanical, physical, etc.)
          logical: [],
          mechanical: [],
          physical: [],
          other: []
        },
        flags: []    // Array of {name: string, value: number, bits: object}
      }
    };

    // Detect file type
    if (result.metadata.magic === '7F454C46') result.metadata.fileType = 'ELF';
    else if (result.metadata.magic.startsWith('4D5A')) result.metadata.fileType = 'PE';
    else if (result.metadata.magic === 'CAFEDEAD' || result.metadata.magic === 'FEEDFACE' || result.metadata.magic === 'FEEDFACF') result.metadata.fileType = 'Mach-O';
    else if (result.metadata.magic === '25504446') result.metadata.fileType = 'PDF'; // Example for extension
    // Add more magic numbers as needed for universality

    // Entropy calculation
    const freq = new Array(256).fill(0);
    for (let i = 0; i < size; i++) freq[buffer[i]]++;
    for (let f of freq) {
      if (f > 0) {
        const p = f / size;
        result.metadata.entropy -= p * Math.log2(p);
      }
    }
    result.metadata.entropy = result.metadata.entropy.toFixed(4);

    // Extract strings (printable ASCII >=4 chars)
    let currentStr = '';
    for (let i = 0; i < size; i++) {
      const c = buffer[i];
      if (c >= 32 && c <= 126) {
        currentStr += String.fromCharCode(c);
      } else {
        if (currentStr.length >= 4) result.metadata.strings.push(currentStr);
        currentStr = '';
      }
    }
    if (currentStr.length >= 4) result.metadata.strings.push(currentStr);

    // Format-specific parsing, normalized to universal schema
    if (result.metadata.fileType === 'ELF') {
      parseELF(buffer, size, result.structures);
    } else if (result.metadata.fileType === 'PE') {
      parsePE(buffer, size, result.structures);
    } else if (result.metadata.fileType === 'Mach-O') {
      parseMachO(buffer, size, result.structures);
    } else {
      // Generic raw data: treat as single segment, group by entropy thresholds or fixed chunks
      parseGeneric(buffer, size, result.structures);
    }

    return JSON.stringify(result, null, 2);
  } catch (error) {
    return JSON.stringify({ error: error.message });
  }
}

// Helper: Parse ELF and populate universal structures
function parseELF(buffer, size, structures) {
  const ei_class = buffer[4];
  const ei_data = buffer[5];
  if (ei_data !== 1) throw new Error('Big-endian not supported');
  const is64bit = ei_class === 2;

  // Headers (e_ident, e_type, etc.)
  structures.headers.push({ name: 'ei_class', value: is64bit ? '64-bit' : '32-bit', type: 'integer', offset: 4 });
  structures.headers.push({ name: 'ei_data', value: 'Little-endian', type: 'string', offset: 5 });
  structures.headers.push({ name: 'ei_osabi', value: buffer[7], type: 'integer', offset: 7 });
  structures.headers.push({ name: 'e_type', value: buffer.readUInt16LE(16), type: 'integer', offset: 16 });
  structures.headers.push({ name: 'e_machine', value: buffer.readUInt16LE(18), type: 'integer', offset: 18 });

  let offset = 24;
  structures.headers.push({ name: 'e_entry', value: is64bit ? Number(buffer.readBigUInt64LE(offset)) : buffer.readUInt32LE(offset), type: 'address', offset });
  offset += is64bit ? 8 : 4;
  structures.headers.push({ name: 'e_phoff', value: is64bit ? Number(buffer.readBigUInt64LE(offset)) : buffer.readUInt32LE(offset), type: 'offset', offset });
  offset += is64bit ? 8 : 4;
  const shoff = is64bit ? Number(buffer.readBigUInt64LE(offset)) : buffer.readUInt32LE(offset);
  structures.headers.push({ name: 'e_shoff', value: shoff, type: 'offset', offset });
  offset += is64bit ? 8 : 4 + 4; // Skip flags and ehsize
  offset += 4; // phentsize + phnum
  const shentsize = buffer.readUInt16LE(offset);
  offset += 2;
  const shnum = buffer.readUInt16LE(offset);
  structures.headers.push({ name: 'e_shnum', value: shnum, type: 'integer', offset });
  offset += 2;
  const shstrndx = buffer.readUInt16LE(offset);
  structures.headers.push({ name: 'e_shstrndx', value: shstrndx, type: 'integer', offset });

  // Flags (from e_flags, but simplified)
  structures.flags.push({ name: 'e_flags', value: buffer.readUInt32LE(36), bits: {} }); // Expand bits if needed

  // Tables: Section header table
  const sectionTable = { name: 'section_headers', entries: [] };
  if (shnum > 0 && shoff > 0) {
    const shstr_off = is64bit ? Number(buffer.readBigUInt64LE(shoff + shstrndx * shentsize + 24)) : buffer.readUInt32LE(shoff + shstrndx * shentsize + 16);
    for (let i = 0; i < shnum; i++) {
      const sec_offset = shoff + i * shentsize;
      const sh_name_idx = is64bit ? buffer.readUInt32LE(sec_offset) : buffer.readUInt32LE(sec_offset);
      const sh_type = is64bit ? buffer.readUInt32LE(sec_offset + 4) : buffer.readUInt32LE(sec_offset + 4);
      const sh_flags = is64bit ? Number(buffer.readBigUInt64LE(sec_offset + 8)) : buffer.readUInt32LE(sec_offset + 8);
      const sh_addr = is64bit ? Number(buffer.readBigUInt64LE(sec_offset + 16)) : buffer.readUInt32LE(sec_offset + 12);
      const sh_offset = is64bit ? Number(buffer.readBigUInt64LE(sec_offset + 24)) : buffer.readUInt32LE(sec_offset + 16);
      const sh_size = is64bit ? Number(buffer.readBigUInt64LE(sec_offset + 32)) : buffer.readUInt32LE(sec_offset + 20);
      let name = '';
      let j = shstr_off + sh_name_idx;
      while (buffer[j] !== 0 && j < size) {
        name += String.fromCharCode(buffer[j]);
        j++;
      }
      const entry = { sh_name: name, sh_type, sh_flags, sh_addr, sh_offset, sh_size };
      sectionTable.entries.push(entry);

      // Segments/Sections
      structures.segments.push({ name, offset: sh_offset, size: sh_size, type: getSectionType(sh_type) });

      // Groups (categorize)
      if (name.startsWith('.text') || name.startsWith('.code')) structures.groups.logical.push(name);
      else if (name.startsWith('.data') || name.startsWith('.bss')) structures.groups.physical.push(name);
      else if (name === '.symtab' || name === '.strtab') structures.groups.mechanical.push(name);
      else structures.groups.other.push(name);
    }
  }
  structures.tables.push(sectionTable);

  // Tables: Symbol table (if found)
  const symTable = { name: 'symbols', entries: [] };
  for (let sec of sectionTable.entries) {
    if (sec.sh_type === 2) { // SYMTAB
      const sym_size = is64bit ? 24 : 16;
      const num_syms = sec.sh_size / sym_size;
      const strtab_idx = is64bit ? buffer.readUInt32LE(shoff + sec.sh_index * shentsize + 8) : buffer.readUInt32LE(shoff + sec.sh_index * shentsize + 8); // Assume sh_index is i, but adjust
      const strtab_off = is64bit ? Number(buffer.readBigUInt64LE(shoff + strtab_idx * shentsize + 24)) : buffer.readUInt32LE(shoff + strtab_idx * shentsize + 16);
      for (let s = 0; s < num_syms; s++) {
        const sym_off = sec.sh_offset + s * sym_size;
        const st_name = is64bit ? buffer.readUInt32LE(sym_off) : buffer.readUInt32LE(sym_off);
        const st_value = is64bit ? Number(buffer.readBigUInt64LE(sym_off + 8)) : buffer.readUInt32LE(sym_off + 4);
        let sym_name = '';
        let j = strtab_off + st_name;
        while (buffer[j] !== 0 && j < size) {
          sym_name += String.fromCharCode(buffer[j]);
          j++;
        }
        if (sym_name) symTable.entries.push({ name: sym_name, value: st_value });
      }
      break;
    }
  }
  if (symTable.entries.length > 0) structures.tables.push(symTable);
}

// Helper for section type
function getSectionType(type) {
  switch (type) {
    case 1: return 'PROGBITS';
    case 2: return 'SYMTAB';
    case 3: return 'STRTAB';
    case 8: return 'NOBITS';
    default: return 'Other';
  }
}

// Basic PE parse
function parsePE(buffer, size, structures) {
  // DOS header
  structures.headers.push({ name: 'dos_magic', value: buffer.readUInt16LE(0), type: 'magic', offset: 0 });
  const e_lfanew = buffer.readUInt32LE(60);
  structures.headers.push({ name: 'e_lfanew', value: e_lfanew, type: 'offset', offset: 60 });

  // NT header
  const nt_off = e_lfanew;
  structures.headers.push({ name: 'nt_signature', value: buffer.readUInt32LE(nt_off), type: 'signature', offset: nt_off });
  structures.headers.push({ name: 'machine', value: buffer.readUInt16LE(nt_off + 4), type: 'integer', offset: nt_off + 4 });
  const num_sections = buffer.readUInt16LE(nt_off + 6);
  structures.headers.push({ name: 'numberOfSections', value: num_sections, type: 'integer', offset: nt_off + 6 });
  structures.headers.push({ name: 'characteristics', value: buffer.readUInt16LE(nt_off + 22), type: 'flags', offset: nt_off + 22 });

  // Flags
  structures.flags.push({ name: 'characteristics', value: buffer.readUInt16LE(nt_off + 22), bits: parsePECharacteristics(buffer.readUInt16LE(nt_off + 22)) });

  // Optional header
  const opt_off = nt_off + 24;
  structures.headers.push({ name: 'opt_magic', value: buffer.readUInt16LE(opt_off), type: 'magic', offset: opt_off });
  // Add more optional header fields as name=value

  // Section table
  const sec_off = opt_off + buffer.readUInt16LE(nt_off + 20); // sizeOfOptionalHeader
  const sectionTable = { name: 'section_table', entries: [] };
  for (let i = 0; i < num_sections; i++) {
    const s_off = sec_off + i * 40;
    let name = '';
    for (let j = 0; j < 8; j++) {
      if (buffer[s_off + j] === 0) break;
      name += String.fromCharCode(buffer[s_off + j]);
    }
    const entry = {
      name,
      virtualSize: buffer.readUInt32LE(s_off + 8),
      virtualAddress: buffer.readUInt32LE(s_off + 12),
      sizeOfRawData: buffer.readUInt32LE(s_off + 16),
      pointerToRawData: buffer.readUInt32LE(s_off + 20),
      characteristics: buffer.readUInt32LE(s_off + 36)
    };
    sectionTable.entries.push(entry);

    // Segments
    structures.segments.push({ name, offset: entry.pointerToRawData, size: entry.sizeOfRawData, type: 'PE Section' });

    // Groups
    if (name === '.text') structures.groups.logical.push(name);
    else if (name === '.data' || name === '.rdata') structures.groups.physical.push(name);
    else structures.groups.other.push(name);
  }
  structures.tables.push(sectionTable);
}

// Helper for PE characteristics bits
function parsePECharacteristics(value) {
  return {
    relocs_stripped: (value & 0x0001) !== 0,
    executable: (value & 0x0002) !== 0,
    // Add more bits
  };
}

// Basic Mach-O parse
function parseMachO(buffer, size, structures) {
  const magic = buffer.readUInt32LE(0);
  structures.headers.push({ name: 'magic', value: magic, type: 'magic', offset: 0 });
  structures.headers.push({ name: 'cputype', value: buffer.readUInt32LE(4), type: 'integer', offset: 4 });
  structures.headers.push({ name: 'cpusubtype', value: buffer.readUInt32LE(8), type: 'integer', offset: 8 });
  structures.headers.push({ name: 'filetype', value: buffer.readUInt32LE(12), type: 'integer', offset: 12 });
  const ncmds = buffer.readUInt32LE(16);
  structures.headers.push({ name: 'ncmds', value: ncmds, type: 'integer', offset: 16 });
  structures.headers.push({ name: 'sizeofcmds', value: buffer.readUInt32LE(20), type: 'integer', offset: 20 });
  const flags = buffer.readUInt32LE(24);
  structures.headers.push({ name: 'flags', value: flags, type: 'flags', offset: 24 });

  // Flags
  structures.flags.push({ name: 'flags', value: flags, bits: parseMachOFlags(flags) });

  let offset = magic === 0xFEEDFACF ? 32 : 28; // 64-bit vs 32-bit

  // Load commands table
  const cmdTable = { name: 'load_commands', entries: [] };
  for (let i = 0; i < ncmds; i++) {
    const cmd = buffer.readUInt32LE(offset);
    const cmdsize = buffer.readUInt32LE(offset + 4);
    const entry = { cmd, cmdsize, offset };
    cmdTable.entries.push(entry);

    // Segments (if LC_SEGMENT or LC_SEGMENT_64)
    if (cmd === 0x1 || cmd === 0x19) { // LC_SEGMENT / LC_SEGMENT_64
      let segname = '';
      for (let j = offset + 8; j < offset + 24; j++) {
        if (buffer[j] === 0) break;
        segname += String.fromCharCode(buffer[j]);
      }
      const vmaddr = cmd === 0x19 ? Number(buffer.readBigUInt64LE(offset + 24)) : buffer.readUInt32LE(offset + 24);
      const vmsize = cmd === 0x19 ? Number(buffer.readBigUInt64LE(offset + 32)) : buffer.readUInt32LE(offset + 28);
      const fileoff = cmd === 0x19 ? Number(buffer.readBigUInt64LE(offset + 40)) : buffer.readUInt32LE(offset + 32);
      const filesize = cmd === 0x19 ? Number(buffer.readBigUInt64LE(offset + 48)) : buffer.readUInt32LE(offset + 36);
      structures.segments.push({ name: segname, offset: fileoff, size: filesize, type: 'Mach-O Segment' });

      // Groups (example categorization)
      if (segname === '__TEXT') structures.groups.logical.push(segname);
      else if (segname === '__DATA') structures.groups.physical.push(segname);
      else structures.groups.other.push(segname);
    }

    offset += cmdsize;
  }
  structures.tables.push(cmdTable);
}

// Helper for Mach-O flags bits
function parseMachOFlags(value) {
  return {
    noundefs: (value & 0x00000001) !== 0,
    incrlink: (value & 0x00000002) !== 0,
    // Add more
  };
}

// Generic parse for unknown formats
function parseGeneric(buffer, size, structures) {
  // Fake header: magic as header
  structures.headers.push({ name: 'magic', value: buffer.slice(0, 4).toString('hex'), type: 'string', offset: 0 });

  // Divide into fixed-size segments
  const chunkSize = 1024;
  for (let i = 0; i < size; i += chunkSize) {
    const offset = i;
    const chunkLen = Math.min(chunkSize, size - i);
    structures.segments.push({ name: `chunk_${i / chunkSize}`, offset, size: chunkLen, type: 'Raw' });

    // Groups by entropy (example: high entropy = compressed/mechanical)
    const ent = calculateEntropy(buffer.slice(offset, offset + chunkLen));
    if (ent > 7) structures.groups.mechanical.push(`chunk_${i / chunkSize}`);
    else if (ent < 4) structures.groups.logical.push(`chunk_${i / chunkSize}`);
    else structures.groups.other.push(`chunk_${i / chunkSize}`);
  }

  // No tables/flags for generic
}

// Helper: Entropy for chunk
function calculateEntropy(buf) {
  const len = buf.length;
  if (len === 0) return 0;
  const freq = new Array(256).fill(0);
  for (let i = 0; i < len; i++) freq[buf[i]]++;
  let ent = 0;
  for (let f of freq) {
    if (f > 0) {
      const p = f / len;
      ent -= p * Math.log2(p);
    }
  }
  return ent.toFixed(4);
}

// Usage: node script.js <file_path>
if (process.argv.length !== 3) {
  console.log('Usage: node script.js <path_to_binary_file>');
} else {
  console.log(inspectBinary(process.argv[2]));
}