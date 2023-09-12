// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use cc_measurement::log::CcEventLogReader;
use cc_measurement::CcEventHeader;
use cc_measurement::TcgPcrEventHeader;
use core::mem::size_of;
use td_payload::acpi::get_acpi_tables;
use td_shim::acpi::Ccel;
use zerocopy::{AsBytes, FromBytes};

pub fn event_log_size(event_log: &[u8]) -> Option<usize> {
    let reader = CcEventLogReader::new(event_log)?;

    // The first event is TCG_EfiSpecIDEvent with TcgPcrEventHeader
    let mut size = size_of::<TcgPcrEventHeader>() + reader.pcr_event_header.event_size as usize;

    for (header, _) in reader.cc_events {
        size += size_of::<CcEventHeader>() + header.event_size as usize;
    }

    Some(size)
}

fn get_event_log_from_acpi(acpi_table: &[u8]) -> Option<&'static mut [u8]> {
    if acpi_table.len() < size_of::<Ccel>() {
        return None;
    }

    let ccel = Ccel::read_from(&acpi_table[..size_of::<Ccel>()])?;

    let event_log =
        unsafe { core::slice::from_raw_parts_mut(ccel.lasa as *mut u8, ccel.laml as usize) };

    Some(event_log)
}

pub fn get_event_log() -> &'static mut [u8] {
    // Parse out ACPI tables handoff from firmware and find the event log location
    let ccel = get_acpi_tables()
        .and_then(|tables| tables.iter().find(|&&t| t[..4] == *b"CCEL"))
        .expect("Failed to find CCEL");
    get_event_log_from_acpi(ccel).expect("Fail to get event log according CCEL\n")
}

#[cfg(test)]
mod test {
    use super::*;
    use cc_measurement::TcgEfiSpecIdevent;
    use cc_measurement::TpmlDigestValues;

    const INVALID_CCEL_SIZE: usize = 10;
    const TEST_LAML_SIZE: usize = 0x100;
    const TEST_EVENT_SIZE: usize = 1;

    #[test]
    fn test_get_event_log_from_acpi() {
        let buffer = [0xffu8; TEST_LAML_SIZE];
        let laml = buffer.len() as u64;
        let lasa: u64 = &buffer as *const u8 as u64;
        let mut ccel = Ccel::new(2, 0, laml, lasa);
        let mut acpi = &ccel.as_bytes();
        let event_log = get_event_log_from_acpi(acpi);
        assert_eq!(event_log.unwrap(), buffer);
        let bufer = [1u8; INVALID_CCEL_SIZE];
        let status = get_event_log_from_acpi(&bufer);
        assert!(status.is_none());
    }

    #[test]
    fn test_event_log_size() {
        let mut hdr = TcgPcrEventHeader::new_zeroed();
        let mut pcr_even_header = hdr.as_bytes();
        let tdcgefi = TcgEfiSpecIdevent::default();
        let efispec = tdcgefi.as_bytes();
        let hdr = CcEventHeader {
            mr_index: 1,
            event_type: 10,
            digest: TpmlDigestValues {
                count: 0,
                digests: Default::default(),
            },
            event_size: TEST_EVENT_SIZE as u32,
        };
        let mut cc_header = hdr.as_bytes();
        let mut buffer = [0u8; TEST_LAML_SIZE];
        let mut start = 0;
        let mut end = size_of::<TcgPcrEventHeader>();
        buffer[start..end].copy_from_slice(pcr_even_header);
        start = end;
        end = start + size_of::<TcgEfiSpecIdevent>();
        buffer[start..end].copy_from_slice(efispec);
        start = end;
        end = start + size_of::<CcEventHeader>();
        buffer[start..end].copy_from_slice(cc_header);
        let laml = buffer.len() as u64;
        let lasa: u64 = &buffer as *const u8 as u64;
        let mut ccel = Ccel::new(2, 0, laml, lasa);
        let mut acpi = &ccel.as_bytes();
        let event_log = get_event_log_from_acpi(acpi);
        let res = event_log_size(event_log.unwrap());
        let size = size_of::<TcgPcrEventHeader>() + size_of::<CcEventHeader>() + TEST_EVENT_SIZE;
        assert!(res.is_some());
        assert_eq!(res.unwrap(), size);
    }

    #[test]
    #[should_panic]
    fn test_get_event_log() {
        let mut event_log = get_event_log();
    }
}
