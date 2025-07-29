// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

suite("test_disable_drop_bucket_columns") {
    def  tables = ["test_disable_drop_bucket_columns_dup", "test_disable_drop_bucket_columns_uniq","test_disable_drop_bucket_columns_agg"]
    def keys = ["DUP KEY(k1, k2)", "UNIQUE KEY(k1, k2)", "AGGREGATE KEY(k1, k2)"]
    for (i in 0..<3) {
        def tbl = tables.get(i)
        def key = keys.get(i)
        sql """ DROP TABLE IF EXISTS ${tbl} """
        sql """
        CREATE TABLE IF NOT EXISTS ${tbl}
        (
            k1 DATE,
            k2 INT DEFAULT '10',
            v VARCHAR(32) DEFAULT ''
        ) ${key}
        DISTRIBUTED BY HASH(k1, k2) BUCKETS 5
        PROPERTIES("replication_num" = "1", "light_schema_change" = "true"); 
        """

        test {
            sql """ ALTER TABLE ${tbl} DROP COLUMN k2"""
            exception "Could not drop distribution column"
        }
    }
}