// Copyright © 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

use landlock::{
    path_beneath_rules, Access, AccessFs, BitFlags, PathFdError, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetError, ABI,
};
use std::path::PathBuf;
use thiserror::Error;

use crate::vm_config::LandlockConfig;

pub const READ: u8 = 1 << 0;
pub const WRITE: u8 = 1 << 1;
pub const EXECUTE: u8 = 1 << 2;

#[derive(Debug, Error)]
pub enum LandlockError {
    /// Failed to create Ruleset
    #[error("Error creating ruleset: {0}")]
    CreateRuleSet(#[source] RulesetError),

    /// Failed to add rule
    #[error("Error adding rule to ruleset: {0}")]
    AddRule(#[source] RulesetError),

    /// Failed to restrict self
    #[error("Error restricting self: {0}")]
    RestrictSelf(#[source] RulesetError),

    /// Ruleset is empty
    #[error("Ruleset was previously consumed, cannot add rules to it")]
    RulesetConsumed,

    /// Error opening Path
    #[error("Error opening Path: {0}")]
    OpenPath(#[source] PathFdError),
}

pub struct Landlock {
    ruleset: Option<RulesetCreated>,
    abi: ABI,
}

impl Landlock {
    pub fn new() -> Result<Landlock, LandlockError> {
        let abi = ABI::V3;

        let file_access = AccessFs::from_all(abi);
        let def_ruleset = Ruleset::default()
            .handle_access(file_access)
            .map_err(LandlockError::CreateRuleSet)?;

        let ruleset = def_ruleset.create().map_err(LandlockError::CreateRuleSet)?;

        Ok(Landlock {
            ruleset: Some(ruleset),
            abi,
        })
    }

    pub fn add_rule(
        &mut self,
        path: PathBuf,
        access: BitFlags<AccessFs>,
    ) -> Result<(), LandlockError> {
        if self.ruleset.is_none() {
            return Err(LandlockError::RulesetConsumed);
        }
        // path_beneath_rules in landlock crate handles file and directory access rules.
        // Incoming path/s are passed to path_beneath_rules, so that we don't
        // have to worry about the type of the path.
        let paths = vec![path.clone()];
        let path_beneath_rules = path_beneath_rules(paths, access);
        for rule in path_beneath_rules {
            self.ruleset
                .as_mut()
                .unwrap()
                .add_rule(rule.unwrap())
                .map_err(LandlockError::AddRule)?;
        }
        Ok(())
    }

    fn flags_to_access(&self, flags: u8) -> BitFlags<AccessFs> {
        let mut perms = BitFlags::<AccessFs>::empty();
        if flags & READ != 0 {
            perms |= AccessFs::from_read(self.abi);
        }
        if flags & WRITE != 0 {
            perms |= AccessFs::from_write(self.abi);
        }
        perms
    }

    pub fn add_rule_with_flags(&mut self, path: PathBuf, flags: u8) -> Result<(), LandlockError> {
        if self.ruleset.is_none() {
            return Err(LandlockError::RulesetConsumed);
        }
        self.add_rule(path.to_path_buf(), self.flags_to_access(flags))?;
        Ok(())
    }

    pub fn apply_config(
        &mut self,
        landlock_config: Vec<LandlockConfig>,
    ) -> Result<(), LandlockError> {
        for config in landlock_config {
            self.add_rule(config.path, self.flags_to_access(config.flags))?;
        }
        Ok(())
    }

    pub fn restrict_self(&mut self) -> Result<(), LandlockError> {
        let rs = self.ruleset.take();
        if rs.is_none() {
            return Err(LandlockError::RulesetConsumed);
        }
        rs.unwrap()
            .restrict_self()
            .map_err(LandlockError::RestrictSelf)?;
        Ok(())
    }
}
