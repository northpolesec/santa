// Copyright 2025 North Pole Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// TODO:
// This file should really live in the rednose repo. However, this will
// require having rednose re-export arrow types and rewriting rednose_macro
// to emit these new proxy types. This is due to how crate universe in
// bazel includes the dependencies such that the crates are sort of
// "namespaced". If Santa were to rely on its own arrow dependency while
// also relying on a traits file defined in rednose, the types wouldn't
// align and would result in compilation errors.
//
// For now, leaving these trait definitions in Santa to mitigate namespace
// issues until the rednose proc macro can be rewritten.

use arrow::{
    array::{ArrayBuilder, StructBuilder},
    datatypes::Schema,
    error::ArrowError,
};

/// Every type that wants to participate in the Arrow schema and appear in the
/// Parquet output must implement this trait.
///
/// Do not implement this manually. It is recommended to use the
/// [rednose_macro::arrow_table] macro with `#[arrow_table]`, which also
/// provides a TableBuilder.
pub trait ArrowTable {
    /// An Array Schema object matching the fields in the struct, including
    /// nested structs.
    fn table_schema() -> Schema;

    /// Returns preallocated builders matching the table_schema.
    ///
    /// The arguments help calibrate how much memory is reserved for the
    /// builders:
    ///
    /// * `cap` controls how many items are preallocated
    /// * `list_items` is a multiplier applied when the field is a List (Vec<T>)
    ///   type.
    /// * `string_len` controls how many bytes of memory are reserved for each
    ///   string (the total number of bytes is cap * string_len).
    /// * `binary_len` is like `string_len`, but for Binary (Vec<u8> /
    ///   BinaryString) fields.
    fn builders(
        cap: usize,
        list_items: usize,
        string_len: usize,
        binary_len: usize,
    ) -> Vec<Box<dyn ArrayBuilder>>;
}

/// For each schema table, the [rednose_macro::arrow_table] macro generates an
/// implementation of TableBuilder, named "{table_name}Builder". This trait is
/// used to build Arrow RecordBatches from data in the table schema.
///
/// In addition to an implementation of this trait, the "{table_name}Builder"
/// struct also provides the following generated methods, per column:
///
/// * {column_name}_builder: Returns the concrete ArrayBuilder for the column.
/// * append_{column_name}: Appends a concretely-typed value to the column.
/// * {column_name}: If the column is a nested struct, returns the nested
///   TableBuilder that corresponds to that struct's schema table.
pub trait TableBuilder {
    /// Construct a new builder for the given table. The arguments help
    /// calibrate how much memory is reserved for the builders.
    fn new(cap: usize, list_items: usize, string_len: usize, binary_len: usize) -> Self;

    /// Flush all the current builder data into a RecordBatch. The builder
    /// remains reusable afterwards.
    fn flush(&mut self) -> Result<arrow::array::RecordBatch, arrow::error::ArrowError>;

    /// Allows access to a specific ArrayBuilder by its index. The index is the
    /// same as the order of the corresponding field in the struct that defines
    /// that arrow table. (Starting from 0.)
    ///
    /// Note that generated TableBuilders also contains constants with indices
    /// of each field, and type-checked accessors for each builder. This method
    /// is useful for dynamic access.
    fn builder<T: ArrayBuilder>(&mut self, i: usize) -> Option<&mut T>;

    /// Same as builder, but without the generic parameter. Because of Rust's
    /// awkward type system, this is the only reasonable way to loop over
    /// builders of different subtypes.
    fn dyn_builder(&mut self, i: usize) -> Option<&dyn ArrayBuilder>;

    /// This has the same effect as calling [StructBuilder::append_null], but
    /// has a recursive effect on all the nested fields. (This is arguably how
    /// [StructBuilder::append_null] should behave. See
    /// https://github.com/apache/arrow-rs/issues/7192.)
    ///
    /// Calling this on the root TableBuilder will panic.
    fn append_null(&mut self);

    /// If this table builder was returned from another table builder, then
    /// return the StructBuilder that contains this table builder's array
    /// buffers. (For the root builder, this returns None.)
    fn as_struct_builder(&mut self) -> Option<&mut StructBuilder>;

    /// Tries to automatically set the remaining columns on row `n`.
    ///
    /// Also see [autocomplete_row].
    ///
    /// Row `n` must be an incomplete row.
    ///
    /// Row N is incomplete if some column builders have a `len` of N, while
    /// others have a `len` of N-1. This fails if more than one row is
    /// incomplete. See [TableBuilder::row_count].
    ///
    /// For most values, this will attempt to append a null, or fail if the
    /// column is not nullable. Structs are handled recursivelly. Lists are
    /// appended in whatever state they're in.
    fn autocomplete_row(&mut self, n: usize) -> Result<(), arrow::error::ArrowError>;

    /// Returns the number of columns in this builder.
    fn column_count(&self) -> usize;

    /// Returns the number of incomplete and complete rows in the builder. (A
    /// row is complete if it has a value in each column.)
    fn row_count(&mut self) -> (usize, usize);

    #[cfg(debug_assertions)]
    /// Debugging helper that returns a human-readable list of columns and their
    /// row counts. (This can help when you're trying to figure out what value
    /// out of 150 you forgot to set.)
    fn debug_row_counts(&mut self) -> Vec<(String, usize, usize)>;
}

/// Convenience wrapper around [TableBuilder::autocomplete_row].
///
/// Automatically figures out the number of incomplete rows, checks invariants
/// and calls the trait method with the correct `n`.
pub fn autocomplete_row<T: TableBuilder>(table_builder: &mut T) -> Result<(), ArrowError> {
    let (complete, incomplete) = table_builder.row_count();
    if complete == incomplete {
        return Err(ArrowError::ComputeError(format!(
            "No incomplete row in {}",
            std::any::type_name_of_val(table_builder)
        )));
    }
    if complete != incomplete - 1 {
        return Err(ArrowError::ComputeError(format!(
            "More than one incomplete row in {} (complete: {}, incomplete: {})",
            std::any::type_name_of_val(table_builder),
            complete,
            incomplete
        )));
    }
    table_builder.autocomplete_row(incomplete)?;

    // This is here in case any autocomplete bugs surface later. (They
    // shouldn't.)
    #[cfg(debug_assertions)]
    debug_assert_row_counts(table_builder);

    Ok(())
}

#[cfg(debug_assertions)]
pub fn debug_dump_column_row_counts<T: TableBuilder>(table_builder: &mut T) -> String {
    table_builder
        .debug_row_counts()
        .iter()
        .map(|(col, lo, hi)| format!("{}: {} / {}", col, lo, hi))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(debug_assertions)]
fn debug_assert_row_counts<T: TableBuilder>(table_builder: &mut T) {
    let (lo, hi) = table_builder.row_count();
    let debug_counts = debug_dump_column_row_counts(table_builder);
    for i in 0..table_builder.column_count() {
        let builder = table_builder.dyn_builder(i).unwrap();
        assert_eq!(
            builder.len(),
            hi,
            "still an incomplete row in {} column {} after autocomplete\n{}",
            std::any::type_name_of_val(table_builder),
            i,
            debug_counts
        );
    }
    assert_eq!(
        lo,
        hi,
        "row_count for {} still shows incomplete rows after autocomplete\n{}",
        std::any::type_name_of_val(table_builder),
        debug_counts
    );
}
