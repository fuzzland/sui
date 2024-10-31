// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeSet, HashMap};

use move_binary_format::errors::{PartialVMError, PartialVMResult, VMResult};
use move_core_types::{
    identifier::IdentStr,
    language_storage::{ModuleId, TypeTag},
};

use crate::shared::types::{PackageStorageId, RuntimePackageId};

/// An execution context that remaps the modules referred to at runtime according to a linkage
/// table, allowing the same module in storage to be run against different dependencies.
#[derive(Debug, Clone)]
pub struct LinkageContext {
    /// The root package address for linkage checking. For publication, this should be the address
    /// of publication. For loading, this should be the root address being loaded.
    pub root_package: PackageStorageId,
    // Linkage Table. This is a table indicating, for a given Address, how it should be linked.
    // This is purely for versioning. Assume some Package P is published at V1 and V2 as:
    //  P V1 -> 0xCAFE
    //  P V2 -> 0xDEAD
    // All calls to P in the root package will call 0xCAFE as the Runtime ID, but during loading
    // and JIT compilation we need to rewrite these. The linkage table here will redirect 0xCAFE to
    // 0xDEAD for this purpose.
    pub linkage_table: HashMap<RuntimePackageId, PackageStorageId>,
}

impl LinkageContext {
    pub fn new(
        root_package: PackageStorageId,
        linkage_table: HashMap<RuntimePackageId, PackageStorageId>,
    ) -> Self {
        Self {
            root_package,
            linkage_table,
        }
    }

    pub fn contains_key(&self, address: &RuntimePackageId) -> bool {
        self.linkage_table.contains_key(address)
    }

    /// Add a Runtime ID -> Storage ID entry to the linkage table. This allows for shadowing of
    /// exsting Runtime ID definitions, but will error of the Storage ID is already being used as a
    /// Runtime ID in the linkage.
    pub fn add_entry(
        &mut self,
        runtime_id: RuntimePackageId,
        storage_id: PackageStorageId,
    ) -> PartialVMResult<()> {
        if self.linkage_table.contains_key(&storage_id) {
            return Err(
                PartialVMError::new(move_core_types::vm_status::StatusCode::LINKER_ERROR)
                    .with_message(format!(
                        "Storage ID {storage_id} is a key in the current linkage context"
                    )),
            );
        };
        self.linkage_table.insert(runtime_id, storage_id);
        Ok(())
    }

    /// Adds the addresses mentioned in a type tags to the linkage context as follows: if the
    /// address is already a key, ignore it; if it is not, add it as a reflextive entry.
    ///
    /// This is to help harness/testing cases, where we might find type arguments to calls that would
    /// otherwise not appear in any dependencies in the target module (e.g., we are calling it
    /// polymorphicall).
    pub fn add_type_arg_addresses_reflexive<'a>(
        &mut self,
        type_tags: impl IntoIterator<Item = &'a TypeTag>,
    ) {
        let type_arg_addresses = type_tags.into_iter().fold(BTreeSet::new(), |mut acc, tag| {
            acc.extend(tag.all_addresses());
            acc
        });
        for arg_address in type_arg_addresses {
            if !self.contains_key(&arg_address) {
                let _ = self.add_entry(arg_address, arg_address);
            }
        }
    }

    /// The root package identifies the root package to use for mapping from runtime `ModuleId`s to
    /// the `ModuleId`s in storage that they are loaded from as returned by `relocate`.
    pub fn root_package(&self) -> PackageStorageId {
        self.root_package
    }

    /// Translate the runtime `module_id` to the on-chain `ModuleId` that it should be loaded from.
    pub fn relocate(&self, module_id: &ModuleId) -> PartialVMResult<ModuleId> {
        self.linkage_table
            .get(module_id.address())
            .map(|remapped_address| ModuleId::new(*remapped_address, module_id.name().into()))
            .ok_or_else(|| {
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

    /// Gives the root package plus transitive dependencies (as stored package IDs) of the linking
    /// context. This is computed as the values of the linkage table, which must necessarily
    /// include the root package address.
    pub fn all_packages(&self) -> VMResult<BTreeSet<PackageStorageId>> {
        Ok(self
            .linkage_table
            .values()
            .cloned()
            .collect::<BTreeSet<_>>())
    }

    /// Gives the transitive dependencies (as stored package IDs) of the linking context. This is
    /// computed as the values of the linkage table, minus the root package address.
    pub fn all_package_dependencies(&self) -> VMResult<BTreeSet<PackageStorageId>> {
        Ok(self
            .linkage_table
            .values()
            .filter(|id| *id != &self.root_package)
            .cloned()
            .collect::<BTreeSet<_>>())
    }
}