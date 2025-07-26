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

use crate::traits::*;
use arrow::{
    array::{ArrayBuilder, StructBuilder},
    datatypes::{Field, Schema, TimeUnit},
};
use rednose_macro::arrow_table;
use std::{collections::HashMap, time::Duration};

#[arrow_table]
pub struct Common {
    pub boot_uuid: String,
}
