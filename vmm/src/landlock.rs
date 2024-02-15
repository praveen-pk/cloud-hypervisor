// Copyright © 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
use crate::{Deserialize, Serialize};
use bitflags::bitflags;

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq,  Serialize, Deserialize)]
    pub struct Perms: u8 {
        const READ = 0b00000001;
        const WRITE = 0b00000010;
        const EXECUTE = 0b00000100;
    }
}
