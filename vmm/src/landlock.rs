// Copyright © 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
use crate::{Deserialize, Serialize};
use bitflags::bitflags;
use thiserror::Error;

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq,  Serialize, Deserialize)]
    pub struct Perms: u8 {
        const READ = 0b00000001;
        const WRITE = 0b00000010;
        const EXECUTE = 0b00000100;
    }
}
use crate::vm_config::LandlockConfig;
use landlock::{
    path_beneath_rules, Access, AccessFs, BitFlags, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr, RulesetError, ABI,
};
use std::io::Error as IoError;
use std::path::PathBuf;

#[derive(Debug, Error)]
pub enum LandlockError {
    /// All RulesetErrors from Landlock library are wrapped in this error
    #[error("Error creating/adding/restricting ruleset: {0}")]
    ManageRuleset(#[source] RulesetError),

    /// Error opening path
    #[error("Error opening path: {0}")]
    OpenPath(#[source] IoError),
}
// https://docs.rs/landlock/latest/landlock/enum.ABI.html for more info on ABI
static ABI: ABI = ABI::V3;

pub struct Landlock {
    ruleset: RulesetCreated,
}

impl Landlock {
    pub fn new() -> Result<Landlock, LandlockError> {
        let file_access = AccessFs::from_all(ABI);

        let def_ruleset = Ruleset::default()
            .handle_access(file_access)
            .map_err(LandlockError::ManageRuleset)?;

        // By default, ruelsets are created in `BestEffort` mode. This lets Landlock
        // to enable all the supported rules and silently ignore the unsupported ones.
        let ruleset = def_ruleset.create().map_err(LandlockError::ManageRuleset)?;

        Ok(Landlock { ruleset })
    }

    pub fn add_rule(
        &mut self,
        path: PathBuf,
        access: BitFlags<AccessFs>,
    ) -> Result<(), LandlockError> {
        // path_beneath_rules in landlock crate handles file and directory access rules.
        // Incoming path/s are passed to path_beneath_rules, so that we don't
        // have to worry about the type of the path.
        let paths = vec![path.clone()];
        let path_beneath_rules = path_beneath_rules(paths, access);
        self.ruleset
            .as_mut()
            .add_rules(path_beneath_rules)
            .map_err(LandlockError::ManageRuleset)?;
        Ok(())
    }

    fn perms_to_access(&self, perms: Perms) -> BitFlags<AccessFs> {
        let mut access = BitFlags::<AccessFs>::empty();
        if perms & Perms::READ != Perms::empty() {
            access |= AccessFs::from_read(ABI);
        }
        if perms & Perms::READ != Perms::empty() {
            access |= AccessFs::from_write(ABI);
        }
        access
    }

    pub fn add_rule_with_perms(
        &mut self,
        path: PathBuf,
        perms: Perms,
    ) -> Result<(), LandlockError> {
        self.add_rule(path.to_path_buf(), self.perms_to_access(perms))?;
        Ok(())
    }

    pub fn apply_config(
        &mut self,
        landlock_config: Vec<LandlockConfig>,
    ) -> Result<(), LandlockError> {
        for config in landlock_config {
            self.add_rule(config.path, self.perms_to_access(config.perms))?;
        }
        Ok(())
    }

    pub fn restrict_self(self) -> Result<(), LandlockError> {
        self.ruleset
            .restrict_self()
            .map_err(LandlockError::ManageRuleset)?;
        Ok(())
    }
}
