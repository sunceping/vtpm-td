// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use spdmlib::error::{SpdmResult, SPDM_STATUS_INVALID_CERT};
use tdx_tdcall::{
    td_call,
    tdreport::{TdxReport, TD_REPORT_SIZE},
    TdcallArgs,
};

const TDCALL_VERIFYREPORT: u64 = 22;
const TD_REPORT_MAC_SIZE: usize = 0x100;
const TD_REPORT_MAC_BUF_SIZE: usize = 2 * TD_REPORT_MAC_SIZE;

struct TdxReportMacBuf {
    buf: [u8; TD_REPORT_MAC_BUF_SIZE],
    start: usize,
    offset: usize,
    end: usize,
}

impl TdxReportMacBuf {
    fn new() -> Self {
        let mut buf = TdxReportMacBuf {
            buf: [0u8; TD_REPORT_MAC_BUF_SIZE],
            start: 0,
            offset: 0,
            end: 0,
        };
        buf.adjust();
        buf
    }

    fn adjust(&mut self) {
        self.start = self.buf.as_ptr() as *const u8 as usize;
        self.offset = TD_REPORT_MAC_SIZE - (self.start & (TD_REPORT_MAC_SIZE - 1));
        self.end = self.offset + TD_REPORT_MAC_SIZE;
    }

    fn report_mac_buf_start(&mut self) -> u64 {
        &mut self.buf[self.offset] as *mut u8 as u64
    }

    fn report_mac_buf_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.offset..self.end]
    }
}

pub fn verify_td_report(td_report: &[u8]) -> SpdmResult {
    if td_report.len() != TD_REPORT_SIZE {
        return Err(SPDM_STATUS_INVALID_CERT);
    }

    let mut td_report_mac = TdxReportMacBuf::new();
    td_report_mac.adjust();

    let addr = td_report_mac.report_mac_buf_start();
    td_report_mac
        .report_mac_buf_mut()
        .copy_from_slice(&td_report[..TD_REPORT_MAC_SIZE]);

    let mut args = TdcallArgs {
        rax: TDCALL_VERIFYREPORT,
        rcx: addr,
        ..Default::default()
    };

    let ret = td_call(&mut args);
    if ret != 0 {
        log::error!("tdcall_verifyreport failed with {:X?}\n", args.r10);
        return Err(SPDM_STATUS_INVALID_CERT);
    }

    let mut report = TdxReport::default();
    let mut all_zero = true;
    report.as_bytes_mut().copy_from_slice(td_report);
    for v in report.td_info.rtmr3.iter() {
        if *v != 0u8 {
            all_zero = false;
            break;
        }
    }

    if !all_zero {
        log::error!("rtmr3 is not all zero! - {:02x?}\n", report.td_info.rtmr3);
        return Err(SPDM_STATUS_INVALID_CERT);
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use core::mem::size_of;
    use core::mem::align_of;

    #[repr(align(256))]
    struct TEST {
        buf: [u8; TD_REPORT_MAC_SIZE],
    }

    #[test]
    fn test_tdx_report_mac_buf() {

        let test = TEST {
            buf: [0u8; TD_REPORT_MAC_SIZE]
        };
        let addres = test.buf.as_ptr() as *const u8 as usize;
        print!("buffer is {:x}\n", addres);
        let mut buffer = TdxReportMacBuf::new();
        // assert_eq!(
        //     buffer.report_mac_buf_start(),
        //     (buffer.start + buffer.offset) as u64
        // );
        buffer.adjust();
        print!("buffer is {:x}\n", buffer.start);
        print!("buffer is {}\n", buffer.offset);
        // let data = buffer.report_mac_buf_mut();
        // print!("len is {}\n", data.len());
        // // for  d in data {
        // //     print!("d is {}\n",d);
        // // }
        // // assert_eq!(buffer.end, TD_REPORT_MAC_BUF_SIZE);
        let mac_address = buffer.report_mac_buf_start();
        print!("buffer adddress is 0x{:x}\n", mac_address);

        let size = size_of::<TdxReportMacBuf>();
        print!("size is {}\n", size);
        // print!("buffer start is 0x{:X}\n", buffer.start);
        // print!(
        //     "buffer start + offset is 0x{:X}\n",
        //     buffer.start + buffer.offset
        // );
        // print!("buffer offset is {}\n", buffer.offset);
        // print!("buffer end is {}\n", buffer.end);
    }

    #[test]
    fn test_verify_td_report_error_data() {
        let mut td_report: [u8; 0x1000] = [0xff; 0x1000];
        let res = verify_td_report(&mut td_report);
        assert!(res.is_err());
    }

    #[test]
    #[should_panic]
    fn test_verify_td_report(){
        let mut td_report: [u8; 1024] = [0xff; 1024];
        let res = verify_td_report(&mut td_report);
        assert!(res.is_err());     
    }

}