// Copyright © 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

use landlock::{
    Access, AccessFs, PathBeneath, Ruleset,RulesetCreated,
    RulesetCreatedAttr, RulesetError, ABI, RulesetAttr, PathFd, PathFdError
};
use std::{sync::Mutex, path::PathBuf};
use thiserror::Error;

use crate::vm_config::LandLockConfig;

pub const READ: u8 = 1 << 0;
pub const WRITE: u8 = 1 << 1;
pub const EXECUTE: u8 = 1 << 2;

#[derive(Debug, Error)]
pub enum LandlockError{
    /// Failed to create Ruleset
    #[error("Error Creating ruleset: {0}")]
    CreateRuleSet(#[source] RulesetError),
    /// Failed to Add Rule
    #[error("Error Adding Rule: {0}")]
    AddRule(#[source] RulesetError),

    /// Failed to restrict self
    #[error("Error restricting self: {0}")]
    RestrictSelf(#[source] RulesetError),

    #[error("Error opening Path: {0}")]
    OpenPath(#[source] PathFdError),
}

pub struct LandLock {
    //PPK_TODO: Remove Mutex here, no need to share across threads
    ruleset: Option<Mutex<RulesetCreated>>,
    abi: ABI
}

pub enum LandLockAccess{
    FileRead,
    FileWrite,
    DirRead,
    DirWrite,
}

impl LandLock {
    pub fn new() -> Result<LandLock, LandlockError> {
        let abi = ABI::V3;

        // PPK_TODO: Disable TCP Access by default
        let file_access = AccessFs::from_all(abi);
        let def_ruleset = Ruleset::default().handle_access(file_access).map_err(|e| LandlockError::CreateRuleSet(e))?;

        let ruleset = def_ruleset
            .create()
            .map_err(|e| LandlockError::CreateRuleSet(e))?;

            Ok(LandLock{
                ruleset: Some(Mutex::new(ruleset)),
                abi: abi})
    }

    pub fn apply_config(&mut self, landlock_config: Vec<LandLockConfig>) -> Result<(), LandlockError> {
        for config in landlock_config {
            //PPK_TODO: Translate the perms here
            if config.path.is_file(){
                self.add_rule(config.path, LandLockAccess::FileWrite)?;
            }
            else if config.path.is_dir() {
                self.add_rule(config.path, LandLockAccess::DirWrite)?;
            }
        }
        Ok(())
    }

    pub fn add_rule(&mut self, path: PathBuf, rule: LandLockAccess) -> Result<(), LandlockError> {
        let path =PathFd::new(path).map_err(|e| LandlockError::OpenPath(e) )?;
        //PPK_TODO: Fix these rules

        match rule {
            LandLockAccess::FileRead => {
                let access_read = AccessFs::from_read(self.abi);
                self.ruleset
                .as_mut()
                .unwrap()
                .lock()
                .unwrap()
                .as_mut()
                .add_rule(PathBeneath::new(path, access_read)).map_err(|e| LandlockError::AddRule(e))?;
            },
            LandLockAccess::FileWrite => {
                let _access_write = AccessFs::from_write(self.abi);
                let access_all = AccessFs::from_all(self.abi);
                self.ruleset
                .as_mut()
                .unwrap()
                .lock()
                .unwrap()
                .as_mut()
                .add_rule(PathBeneath::new(path, access_all)).map_err(|e| LandlockError::AddRule(e))?;
            },
            LandLockAccess::DirWrite => {
                let _access_write = AccessFs::from_write(self.abi);
                let access_all = AccessFs::from_all(self.abi);
                self.ruleset
                .as_mut()
                .unwrap()
                .lock()
                .unwrap()
                .as_mut()
                .add_rule(PathBeneath::new(path, access_all)).map_err(|e| LandlockError::AddRule(e))?;
            },
            LandLockAccess::DirRead => {
                let _access_write = AccessFs::from_write(self.abi);
                let access_all = AccessFs::from_all(self.abi);
                self.ruleset
                .as_mut()
                .unwrap()
                .lock()
                .unwrap()
                .as_mut()
                .add_rule(PathBeneath::new(path, access_all)).map_err(|e| LandlockError::AddRule(e))?;
            },
        }
        Ok(())
    }


    pub fn restrict_self(&mut self) -> Result<(), LandlockError> {
        let rs = self.ruleset.take().unwrap().into_inner().unwrap();
        rs.restrict_self().map_err(|e| LandlockError::RestrictSelf(e))?;
        Ok(())
    }
}

pub fn landlock_thread() -> Result<(), LandlockError> {
    let abi = ABI::V3;
    let file_access = AccessFs::from_all(abi);
    let def_ruleset = Ruleset::default().handle_access(file_access).map_err(|e| LandlockError::CreateRuleSet(e))?;
    let ruleset = def_ruleset.create().map_err(|e| LandlockError::CreateRuleSet(e))?;

    ruleset.restrict_self().map_err(|e| LandlockError::RestrictSelf(e))?;
    Ok(())
}
