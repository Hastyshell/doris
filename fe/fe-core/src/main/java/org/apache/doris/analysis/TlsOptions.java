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

package org.apache.doris.analysis;

import org.apache.doris.common.Pair;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * TLS certificate requirement options for CREATE/ALTER USER.
 * It mirrors PasswordOptions style to keep parser payload compact.
 */
public class TlsOptions {
    private final boolean hasRequireClause;
    private final boolean requireNone;
    private final List<Pair<String, String>> tlsOptions;

    private TlsOptions(boolean hasRequireClause, boolean requireNone, List<Pair<String, String>> tlsOptions) {
        this.hasRequireClause = hasRequireClause;
        this.requireNone = requireNone;
        this.tlsOptions = tlsOptions == null ? Collections.emptyList() : Collections.unmodifiableList(tlsOptions);
    }

    public static TlsOptions notSpecified() {
        return new TlsOptions(false, false, Collections.emptyList());
    }

    public static TlsOptions requireNone() {
        return new TlsOptions(true, true, Collections.emptyList());
    }

    public static TlsOptions of(List<Pair<String, String>> options) {
        return new TlsOptions(true, false, options == null ? Collections.emptyList() : options);
    }

    public boolean hasRequireClause() {
        return hasRequireClause;
    }

    public boolean isRequireNone() {
        return requireNone;
    }

    public List<Pair<String, String>> getTlsOptions() {
        return tlsOptions;
    }

    /**
     * Returns SQL fragment without leading space. Empty string means no REQUIRE clause.
     */
    public String toSql() {
        if (!hasRequireClause) {
            return "";
        }
        if (requireNone) {
            return "REQUIRE NONE";
        }
        if (tlsOptions.isEmpty()) {
            return "REQUIRE NONE"; // defensive; should not happen
        }
        String body = tlsOptions.stream()
                .filter(Objects::nonNull)
                .map(opt -> opt.first + " '" + opt.second + "'")
                .collect(Collectors.joining(" AND "));
        return "REQUIRE " + body;
    }
}
