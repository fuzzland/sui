// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeSet, HashMap};

use move_binary_format::errors::{PartialVMError, PartialVMResult, VMResult};
use move_core_types::{
    account_address::AccountAddress, identifier::IdentStr, language_storage::ModuleId,
};

/// An execution context that remaps the modules referred to at runtime according to a linkage
/// table, allowing the same module in storage to be run against different dependencies.
#[derive(Debug)]
pub struct LinkageContext {
    /// The root package address for linkage checking. For publication, this should be the address
    /// of publication. For loading, this should be the root address being loaded.
    pub root_package: AccountAddress,
    // Linkage Table. This is a table indicating, for a given Address, how it should be linked.
    // This is purely for versioning. Assume some Package P is published at V1 and V2 as:
    //  P V1 -> 0xCAFE
    //  P V2 -> 0xDEAD
    // All calls to P in the root package will call 0xCAFE as the Runtime ID, but during loading
    // and JIT compilation we need to rewrite these. The linkage table here will redirect 0xCAFE to
    // 0xDEAD for this purpose.
    pub linkage_table: HashMap<AccountAddress, AccountAddress>,
}

impl LinkageContext {
    pub fn new(
        root_package: AccountAddress,
        linkage_table: HashMap<AccountAddress, AccountAddress>,
    ) -> Self {
        Self {
            root_package,
            linkage_table,
        }
    }

    /// The root package identifies the root package to use for mapping from runtime `ModuleId`s to
    /// the `ModuleId`s in storage that they are loaded from as returned by `relocate`.
    pub fn root_package(&self) -> AccountAddress {
        self.root_package
    }

    /// Translate the runtime `module_id` to the on-chain `ModuleId` that it should be loaded from.
    pub fn relocate(&self, module_id: &ModuleId) -> PartialVMResult<ModuleId> {
        self.linkage_table
            .get(module_id.address())
            .map(|remapped_address| ModuleId::new(*remapped_address, module_id.name().into()))
            .ok_or({
                PartialVMError::new(move_core_types::vm_status::StatusCode::LINKER_ERROR)
                    .with_message(format!("Did not find {module_id} in linkage table"))
            })
    }

    /// Translate the runtime fully-qualified struct name to the on-chain `ModuleId` that originally
    /// defined that type.
    /// TODO: FIX THIS WHEN THE TYPE ORIGIN TABLE EXISTS
    pub fn defining_module(
        &self,
        module_id: &ModuleId,
        _struct: &IdentStr,
    ) -> PartialVMResult<ModuleId> {
        self.relocate(module_id)
    }

    /// Gives the transitive dependencies (as stored package IDs) of the linking context. This is
    /// computed as the values of the linkage table, minus the root package address.
    pub fn all_package_dependencies(&self) -> VMResult<BTreeSet<AccountAddress>> {
        Ok(self
            .linkage_table
            .values()
            .filter(|id| *id != &self.root_package)
            .cloned()
            .collect::<BTreeSet<_>>())
    }
}