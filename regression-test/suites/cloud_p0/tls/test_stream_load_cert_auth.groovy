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

import org.apache.doris.regression.suite.ClusterOptions

suite('test_stream_load_cert_auth', 'docker, p0') {
    // This test verifies TLS certificate-based authentication for Stream Load via BE.
    // It tests the complete data flow:
    //   Client -> BE HTTPS -> BE extracts cert info -> TCertBasedAuth in Thrift -> FE verifies SAN
    //
    // Requirements:
    // 1. Enterprise version with CertificateBasedAuthVerifier
    // 2. Docker environment for dynamic certificate generation with correct SANs
    //
    // Test cases:
    //   SL-01: SAN matching + correct password -> success
    //   SL-02: No TLS requirement + password auth -> success
    //   SL-03: ignore_password=true + wrong password -> success (cert only)
    //   SL-04: SAN mismatch -> failure
    //   SL-05: No certificate + REQUIRE SAN -> failure
    //   SL-06: Certificate without SAN extension -> failure
    //   SL-07: Two-phase commit with cert auth -> success
    //   SL-08: ALTER USER add/remove REQUIRE SAN -> dynamic effect

    def testName = "test_stream_load_cert_auth"

    def options = new ClusterOptions()
    options.setFeNum(1)
    options.setBeNum(1)
    options.cloudMode = true

    // Add TLS configuration to all node types (initially disabled, will enable after cert deploy)
    def tlsConfigs = [
        'enable_tls=false',
        'tls_verify_mode=verify_peer',
        'tls_certificate_path=/tmp/certs/server.crt',
        'tls_private_key_path=/tmp/certs/server.key',
        'tls_ca_certificate_path=/tmp/certs/ca.crt',
        'tls_cert_refresh_interval_seconds=5'
    ]

    options.feConfigs += tlsConfigs
    options.beConfigs += tlsConfigs
    options.msConfigs += tlsConfigs
    options.recycleConfigs += tlsConfigs

    def localCertDir = "/tmp/${testName}"

    docker(options) {
        sql """ CREATE DATABASE IF NOT EXISTS ${context.dbName}; """

        // Get all node IPs
        def frontends = cluster.getAllFrontends()
        def backends = cluster.getAllBackends()
        def metaservices = cluster.getAllMetaservices()
        def recyclers = cluster.getAllRecyclers(false)

        logger.info("=== Cluster nodes ===")
        frontends.each { fe -> logger.info("FE[${fe.index}] - Host: ${fe.host}, HTTP Port: ${fe.httpPort}") }
        backends.each { be -> logger.info("BE[${be.index}] - Host: ${be.host}, HTTP Port: ${be.httpPort}") }

        // Collect all unique IPs
        def allIps = []
        frontends.each { fe -> if (!allIps.contains(fe.host)) allIps.add(fe.host) }
        backends.each { be -> if (!allIps.contains(be.host)) allIps.add(be.host) }
        metaservices.each { ms -> if (!allIps.contains(ms.host)) allIps.add(ms.host) }
        recyclers.each { rc -> if (!allIps.contains(rc.host)) allIps.add(rc.host) }
        logger.info("All unique IPs: ${allIps}")

        // Helper: Run command
        def runCommand = { String cmd, String errorMsg ->
            logger.info("Executing: ${cmd}")
            def proc = ["bash", "-lc", cmd].execute()
            def stdout = new StringBuilder()
            def stderr = new StringBuilder()
            proc.waitForProcessOutput(stdout, stderr)
            if (proc.exitValue() != 0) {
                logger.error("Command failed: ${cmd}")
                logger.error("stdout: ${stdout}")
                logger.error("stderr: ${stderr}")
                assert false : errorMsg
            }
            return stdout.toString().trim()
        }

        // Get current IP (runner container)
        def currentIp = runCommand('''ip -4 addr show eth0 | grep -oP "(?<=inet\\s)\\d+(\\.\\d+){3}"''', "Failed to get current IP")
        logger.info("Current IP: ${currentIp}")

        // === Certificate Generation ===
        logger.info("=== Generating TLS certificates ===")
        runCommand("mkdir -p ${localCertDir}", "Failed to create cert directory")

        // Generate CA
        runCommand("openssl genpkey -algorithm RSA -out ${localCertDir}/ca.key -pkeyopt rsa_keygen_bits:2048", "Failed to generate CA key")
        runCommand("openssl req -new -x509 -days 3650 -key ${localCertDir}/ca.key -out ${localCertDir}/ca.crt " +
                   "-subj '/C=CN/ST=Beijing/L=Beijing/O=Doris/OU=Test/CN=DorisCA'", "Failed to generate CA cert")

        // Build SAN entries for server cert (includes all node IPs)
        def sanIpEntries = allIps.withIndex().collect { ip, idx -> "IP.${idx + 3} = ${ip}" }.join('\n')
        def serverOpensslConf = """
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = CN
ST = Beijing
L = Beijing
O = Doris
OU = Test
CN = doris-cluster

[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = fe-1
DNS.3 = be-1
DNS.4 = ms-1
DNS.5 = recycle-1
IP.1 = 127.0.0.1
IP.2 = ${currentIp}
${sanIpEntries}
"""
        new File("${localCertDir}/server_openssl.cnf").text = serverOpensslConf
        logger.info("Created server OpenSSL config with SANs for IPs: ${allIps}")

        // Generate server certificate (used by all nodes)
        runCommand("openssl genpkey -algorithm RSA -out ${localCertDir}/server.key -pkeyopt rsa_keygen_bits:2048", "Failed to generate server key")
        runCommand("openssl req -new -key ${localCertDir}/server.key -out ${localCertDir}/server.csr -config ${localCertDir}/server_openssl.cnf", "Failed to generate server CSR")
        runCommand("openssl x509 -req -days 3650 -in ${localCertDir}/server.csr -CA ${localCertDir}/ca.crt -CAkey ${localCertDir}/ca.key " +
                   "-CAcreateserial -out ${localCertDir}/server.crt -extensions v3_req -extfile ${localCertDir}/server_openssl.cnf", "Failed to sign server cert")

        // === Client Certificates ===
        // Client cert WITH SAN (for SAN matching tests)
        def clientSanValue = "email:test@example.com, DNS:testclient.example.com, URI:spiffe://example.com/testclient"
        def clientSanOpensslConf = """
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = CN
ST = Beijing
L = Beijing
O = Doris
OU = Test
CN = test-client

[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
email.1 = test@example.com
DNS.1 = testclient.example.com
URI.1 = spiffe://example.com/testclient
"""
        new File("${localCertDir}/client_san_openssl.cnf").text = clientSanOpensslConf

        runCommand("openssl genpkey -algorithm RSA -out ${localCertDir}/client_san.key -pkeyopt rsa_keygen_bits:2048", "Failed to generate client SAN key")
        runCommand("openssl req -new -key ${localCertDir}/client_san.key -out ${localCertDir}/client_san.csr -config ${localCertDir}/client_san_openssl.cnf", "Failed to generate client SAN CSR")
        runCommand("openssl x509 -req -days 3650 -in ${localCertDir}/client_san.csr -CA ${localCertDir}/ca.crt -CAkey ${localCertDir}/ca.key " +
                   "-CAcreateserial -out ${localCertDir}/client_san.crt -extensions v3_req -extfile ${localCertDir}/client_san_openssl.cnf", "Failed to sign client SAN cert")

        // Client cert WITHOUT SAN (for no-SAN tests)
        def clientNoSanOpensslConf = """
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
C = CN
ST = Beijing
L = Beijing
O = Doris
OU = Test
CN = test-client-nosan
"""
        new File("${localCertDir}/client_nosan_openssl.cnf").text = clientNoSanOpensslConf

        runCommand("openssl genpkey -algorithm RSA -out ${localCertDir}/client_nosan.key -pkeyopt rsa_keygen_bits:2048", "Failed to generate client no-SAN key")
        runCommand("openssl req -new -key ${localCertDir}/client_nosan.key -out ${localCertDir}/client_nosan.csr -config ${localCertDir}/client_nosan_openssl.cnf", "Failed to generate client no-SAN CSR")
        runCommand("openssl x509 -req -days 3650 -in ${localCertDir}/client_nosan.csr -CA ${localCertDir}/ca.crt -CAkey ${localCertDir}/ca.key " +
                   "-CAcreateserial -out ${localCertDir}/client_nosan.crt", "Failed to sign client no-SAN cert")

        // Fix permissions
        runCommand("chmod 644 ${localCertDir}/*.crt ${localCertDir}/*.key", "Failed to fix cert permissions")

        // Verify certificates
        logger.info("Verifying generated certificates...")
        def serverCertInfo = runCommand("openssl x509 -in ${localCertDir}/server.crt -noout -text | grep -A1 'Subject Alternative Name'", "Failed to verify server cert")
        logger.info("Server cert SAN: ${serverCertInfo}")
        def clientSanCertInfo = runCommand("openssl x509 -in ${localCertDir}/client_san.crt -noout -text | grep -A1 'Subject Alternative Name'", "Failed to verify client SAN cert")
        logger.info("Client SAN cert SAN: ${clientSanCertInfo}")

        // === Deploy Certificates to Containers ===
        logger.info("=== Deploying certificates to containers ===")
        def containerNames = []
        frontends.each { fe -> containerNames.add("doris-${cluster.name}-fe-${fe.index}") }
        backends.each { be -> containerNames.add("doris-${cluster.name}-be-${be.index}") }
        metaservices.each { ms -> containerNames.add("doris-${cluster.name}-ms-${ms.index}") }
        recyclers.each { rc -> containerNames.add("doris-${cluster.name}-recycle-${rc.index}") }

        containerNames.each { container ->
            runCommand("docker exec -i ${container} mkdir -p /tmp/certs", "Failed to create cert dir in ${container}")
            ['ca.crt', 'server.key', 'server.crt'].each { fname ->
                runCommand("docker cp ${localCertDir}/${fname} ${container}:/tmp/certs/${fname}", "Failed to copy ${fname} to ${container}")
            }
            logger.info("Deployed certificates to ${container}")
        }

        // === Enable TLS and Restart Nodes ===
        logger.info("=== Enabling TLS ===")
        def updateConfigFile = { confPath ->
            def configFile = new File(confPath)
            if (!configFile.exists()) {
                logger.warn("Config file not found: ${confPath}")
                return
            }
            def lines = configFile.readLines()
            def newLines = lines.collect { line ->
                if (line.trim().startsWith('enable_tls')) {
                    return 'enable_tls=true'
                }
                return line
            }
            configFile.text = newLines.join('\n')
            logger.info("Updated config: ${confPath}")
        }

        frontends.each { fe -> updateConfigFile(fe.getConfFilePath()) }
        backends.each { be -> updateConfigFile(be.getConfFilePath()) }
        metaservices.each { ms -> updateConfigFile(ms.getConfFilePath()) }
        recyclers.each { recycle -> updateConfigFile(recycle.getConfFilePath()) }

        // Restart nodes
        logger.info("=== Restarting nodes with TLS ===")
        def dorisComposePath = cluster.config.dorisComposePath
        def clusterName = cluster.name

        def restartNodes = { String nodeType, String idFlag ->
            def cmd = "python -W ignore ${dorisComposePath} restart ${clusterName} ${idFlag} --wait-timeout 0 -v --output-json"
            logger.info("Executing: ${cmd}")
            def proc = cmd.execute()
            def stdout = new StringBuilder()
            def stderr = new StringBuilder()
            proc.waitForProcessOutput(stdout, stderr)
            if (proc.exitValue() != 0) {
                logger.error("Restart ${nodeType} failed: ${stderr}")
                throw new Exception("Failed to restart ${nodeType}")
            }
            logger.info("${nodeType} restart initiated")
        }

        def msIds = metaservices.collect { it.index }.join(' ')
        restartNodes('MS', "--ms-id ${msIds}")

        def feIds = frontends.collect { it.index }.join(' ')
        restartNodes('FE', "--fe-id ${feIds}")

        def beIds = backends.collect { it.index }.join(' ')
        restartNodes('BE', "--be-id ${beIds}")

        def recyclerIds = recyclers.collect { it.index }.join(' ')
        restartNodes('Recycler', "--recycle-id ${recyclerIds}")

        logger.info("Waiting for nodes to restart...")
        sleep(40000)

        // === Stream Load Test Setup ===
        def firstFe = frontends[0]
        def firstBe = backends[0]
        def beHost = firstBe.host
        def beHttpPort = firstBe.httpPort

        logger.info("Using BE for Stream Load: ${beHost}:${beHttpPort}")

        // mTLS JDBC connection setup
        def keystorePassword = "doris123"
        def keystorePath = "${localCertDir}/keystore.p12"
        def truststorePath = "${localCertDir}/truststore.p12"

        // Create keystores for JDBC
        runCommand("rm -f ${keystorePath} ${truststorePath}", "Failed to remove old keystores")
        runCommand("openssl pkcs12 -export -in ${localCertDir}/server.crt -inkey ${localCertDir}/server.key " +
                   "-out ${keystorePath} -password pass:${keystorePassword} -name doris-client", "Failed to create keystore")
        runCommand("keytool -import -noprompt -alias ca-cert -file ${localCertDir}/ca.crt " +
                   "-keystore ${truststorePath} -storepass ${keystorePassword} -storetype PKCS12", "Failed to create truststore")

        // Build mTLS JDBC URL
        def baseJdbcUrl = String.format("jdbc:mysql://%s:%s/?useLocalSessionState=true&allowLoadLocalInfile=false",
                                        firstFe.host, firstFe.queryPort)
        def tlsJdbcUrl = org.apache.doris.regression.Config.buildUrlWithDb(
            baseJdbcUrl, context.dbName, keystorePath, keystorePassword, truststorePath, keystorePassword)

        logger.info("Connecting with mTLS JDBC URL")

        // Test configuration
        def testUserBase = "test_sl_cert_user"
        def testPassword = "Test_123456"
        def tableName = "test_stream_load_cert_auth_tbl"
        def sanFull = clientSanValue
        def sanMismatch = "email:wrong@example.com"

        // Client cert paths
        def sanClientCert = "${localCertDir}/client_san.crt"
        def sanClientKey = "${localCertDir}/client_san.key"
        def noSanClientCert = "${localCertDir}/client_nosan.crt"
        def noSanClientKey = "${localCertDir}/client_nosan.key"
        def caCert = "${localCertDir}/ca.crt"

        // Use BE's IP directly (no SNI tricks needed since we have proper SANs)
        def streamLoadHost = beHost

        // Helper: Execute Stream Load via curl
        def executeStreamLoadCurl = { Map params ->
            def user = params.user
            def password = params.password
            def db = params.db ?: context.dbName
            def table = params.table
            def data = params.data
            def certPath = params.certPath
            def keyPath = params.keyPath
            def label = params.label ?: "sl_cert_${UUID.randomUUID().toString().replace('-', '')}"
            def twoPhaseCommit = params.twoPhaseCommit ?: false

            def certOpts = (certPath && keyPath) ? "--cert ${certPath} --key ${keyPath}" : ""
            def twoPhaseHeader = twoPhaseCommit ? '-H "two_phase_commit: true"' : ""

            def cmd = """curl -s -k --cacert ${caCert} \\
                ${certOpts} \\
                -u '${user}:${password}' \\
                -H "Expect: 100-continue" \\
                -H "label: ${label}" \\
                -H "column_separator: ," \\
                ${twoPhaseHeader} \\
                -T - \\
                'https://${streamLoadHost}:${beHttpPort}/api/${db}/${table}/_stream_load' \\
                <<< '${data}' 2>&1"""

            logger.info("Execute Stream Load for user ${user}")
            logger.debug("Command: ${cmd}")

            def cmds = ["/bin/bash", "-c", cmd]
            Process p = cmds.execute()
            def errMsg = new StringBuilder()
            def msg = new StringBuilder()
            p.waitForProcessOutput(msg, errMsg)

            def output = msg.toString().trim()
            def errorOutput = errMsg.toString().trim()
            logger.info("Stream Load response: ${output}")
            if (errorOutput) logger.info("Stream Load stderr: ${errorOutput}")
            logger.info("Exit value: ${p.exitValue()}")

            if (p.exitValue() != 0) {
                return [success: false, output: output, error: errorOutput, exitCode: p.exitValue()]
            }

            try {
                def json = new groovy.json.JsonSlurper().parseText(output)
                def status = json.Status?.toLowerCase()
                def isSuccess = (status == "success" || status == "publish timeout")
                return [success: isSuccess, output: output, json: json, txnId: json.TxnId, label: label, status: status]
            } catch (Exception e) {
                logger.warn("Failed to parse JSON: ${e.message}")
                return [success: false, output: output, error: e.message]
            }
        }

        // Helper: Execute 2PC action via curl
        def execute2PCAction = { Map params ->
            def user = params.user
            def password = params.password
            def db = params.db ?: context.dbName
            def txnId = params.txnId
            def action = params.action
            def certPath = params.certPath
            def keyPath = params.keyPath

            def certOpts = (certPath && keyPath) ? "--cert ${certPath} --key ${keyPath}" : ""

            def cmd = """curl -s -k --cacert ${caCert} \\
                ${certOpts} \\
                -u '${user}:${password}' \\
                -X PUT \\
                'https://${streamLoadHost}:${beHttpPort}/api/${db}/_stream_load_2pc?txn_id=${txnId}&txn_operation=${action}' 2>&1"""

            logger.info("Execute 2PC ${action} for txn ${txnId}")

            def cmds = ["/bin/bash", "-c", cmd]
            Process p = cmds.execute()
            def errMsg = new StringBuilder()
            def msg = new StringBuilder()
            p.waitForProcessOutput(msg, errMsg)

            def output = msg.toString().trim()
            logger.info("2PC ${action} response: ${output}")

            if (p.exitValue() != 0) {
                return [success: false, output: output, error: errMsg.toString()]
            }

            try {
                def json = new groovy.json.JsonSlurper().parseText(output)
                def status = json.status?.toLowerCase()
                return [success: (status == "success"), output: output, json: json, status: status]
            } catch (Exception e) {
                return [success: false, output: output, error: e.message]
            }
        }

        // Connect with mTLS and run tests
        context.connect(context.config.jdbcUser, context.config.jdbcPassword, tlsJdbcUrl) {
            // Cleanup function
            def cleanup = {
                logger.info("Cleaning up test resources...")
                try_sql("DROP TABLE IF EXISTS ${tableName}")
                (1..8).each { i ->
                    try_sql("DROP USER IF EXISTS '${testUserBase}_${i}'@'%'")
                }
            }

            // Save original config
            def origIgnorePassword = "false"
            try {
                def configResult = sql "SHOW FRONTEND CONFIG LIKE 'tls_cert_based_auth_ignore_password'"
                if (!configResult.isEmpty()) {
                    origIgnorePassword = configResult[0][1]
                }
            } catch (Exception e) {
                logger.info("Could not get original config: ${e.message}")
            }

            cleanup()

            try {
                // Create test table
                sql """
                    CREATE TABLE ${tableName} (
                        k1 INT,
                        k2 VARCHAR(100)
                    ) DISTRIBUTED BY HASH(k1) BUCKETS 1
                    PROPERTIES ("replication_num" = "1")
                """
                logger.info("Created test table: ${tableName}")

                sql "ADMIN SET FRONTEND CONFIG ('tls_cert_based_auth_ignore_password' = 'false')"

                // ==================================================================================
                // SL-01: SAN matching + correct password -> success
                // ==================================================================================
                logger.info("=== SL-01: Matching SAN + correct password ===")
                sql "CREATE USER '${testUserBase}_1'@'%' IDENTIFIED BY '${testPassword}' REQUIRE SAN '${sanFull}'"
                sql "GRANT LOAD_PRIV ON ${context.dbName}.${tableName} TO '${testUserBase}_1'@'%'"

                def result1 = executeStreamLoadCurl(
                    user: "${testUserBase}_1",
                    password: testPassword,
                    table: tableName,
                    data: "1,value1\\n2,value2",
                    certPath: sanClientCert,
                    keyPath: sanClientKey
                )
                assertTrue(result1.success, "SL-01 should succeed: ${result1.output}")
                logger.info("SL-01 PASSED")

                def count1 = sql "SELECT COUNT(*) FROM ${tableName}"
                assertTrue(count1[0][0] >= 2, "Data should be loaded")
                sql "TRUNCATE TABLE ${tableName}"

                // ==================================================================================
                // SL-02: No TLS requirement + password auth -> success
                // ==================================================================================
                logger.info("=== SL-02: No TLS requirement + password auth ===")
                sql "CREATE USER '${testUserBase}_2'@'%' IDENTIFIED BY '${testPassword}'"
                sql "GRANT LOAD_PRIV ON ${context.dbName}.${tableName} TO '${testUserBase}_2'@'%'"

                def result2 = executeStreamLoadCurl(
                    user: "${testUserBase}_2",
                    password: testPassword,
                    table: tableName,
                    data: "3,value3",
                    certPath: sanClientCert,
                    keyPath: sanClientKey
                )
                assertTrue(result2.success, "SL-02 should succeed: ${result2.output}")
                logger.info("SL-02 PASSED")
                sql "TRUNCATE TABLE ${tableName}"

                // ==================================================================================
                // SL-03: ignore_password=true + wrong password -> success (cert only)
                // ==================================================================================
                logger.info("=== SL-03: ignore_password=true + wrong password ===")
                sql "ADMIN SET FRONTEND CONFIG ('tls_cert_based_auth_ignore_password' = 'true')"
                sql "CREATE USER '${testUserBase}_3'@'%' IDENTIFIED BY '${testPassword}' REQUIRE SAN '${sanFull}'"
                sql "GRANT LOAD_PRIV ON ${context.dbName}.${tableName} TO '${testUserBase}_3'@'%'"

                def result3 = executeStreamLoadCurl(
                    user: "${testUserBase}_3",
                    password: "wrong_password",
                    table: tableName,
                    data: "4,value4",
                    certPath: sanClientCert,
                    keyPath: sanClientKey
                )
                assertTrue(result3.success, "SL-03 should succeed (password ignored): ${result3.output}")
                logger.info("SL-03 PASSED")
                sql "TRUNCATE TABLE ${tableName}"

                sql "ADMIN SET FRONTEND CONFIG ('tls_cert_based_auth_ignore_password' = 'false')"

                // ==================================================================================
                // SL-04: SAN mismatch -> failure
                // ==================================================================================
                logger.info("=== SL-04: SAN mismatch ===")
                sql "CREATE USER '${testUserBase}_4'@'%' IDENTIFIED BY '${testPassword}' REQUIRE SAN '${sanMismatch}'"
                sql "GRANT LOAD_PRIV ON ${context.dbName}.${tableName} TO '${testUserBase}_4'@'%'"

                def result4 = executeStreamLoadCurl(
                    user: "${testUserBase}_4",
                    password: testPassword,
                    table: tableName,
                    data: "5,value5",
                    certPath: sanClientCert,
                    keyPath: sanClientKey
                )
                assertFalse(result4.success, "SL-04 should fail: SAN mismatch")
                logger.info("SL-04 PASSED")

                // ==================================================================================
                // SL-05: No certificate + REQUIRE SAN -> failure
                // ==================================================================================
                logger.info("=== SL-05: No certificate + REQUIRE SAN ===")
                sql "CREATE USER '${testUserBase}_5'@'%' IDENTIFIED BY '${testPassword}' REQUIRE SAN '${sanFull}'"
                sql "GRANT LOAD_PRIV ON ${context.dbName}.${tableName} TO '${testUserBase}_5'@'%'"

                def result5 = executeStreamLoadCurl(
                    user: "${testUserBase}_5",
                    password: testPassword,
                    table: tableName,
                    data: "6,value6"
                    // No certPath/keyPath
                )
                assertFalse(result5.success, "SL-05 should fail: no certificate")
                logger.info("SL-05 PASSED")

                // ==================================================================================
                // SL-06: Certificate without SAN extension -> failure
                // ==================================================================================
                logger.info("=== SL-06: Certificate without SAN extension ===")
                sql "CREATE USER '${testUserBase}_6'@'%' IDENTIFIED BY '${testPassword}' REQUIRE SAN '${sanFull}'"
                sql "GRANT LOAD_PRIV ON ${context.dbName}.${tableName} TO '${testUserBase}_6'@'%'"

                def result6 = executeStreamLoadCurl(
                    user: "${testUserBase}_6",
                    password: testPassword,
                    table: tableName,
                    data: "7,value7",
                    certPath: noSanClientCert,
                    keyPath: noSanClientKey
                )
                assertFalse(result6.success, "SL-06 should fail: cert has no SAN")
                logger.info("SL-06 PASSED")

                // ==================================================================================
                // SL-07: Two-phase commit with cert auth -> success
                // ==================================================================================
                logger.info("=== SL-07: Two-phase commit ===")
                sql "CREATE USER '${testUserBase}_7'@'%' IDENTIFIED BY '${testPassword}' REQUIRE SAN '${sanFull}'"
                sql "GRANT LOAD_PRIV ON ${context.dbName}.${tableName} TO '${testUserBase}_7'@'%'"

                def result7 = executeStreamLoadCurl(
                    user: "${testUserBase}_7",
                    password: testPassword,
                    table: tableName,
                    data: "8,2pc_test",
                    certPath: sanClientCert,
                    keyPath: sanClientKey,
                    twoPhaseCommit: true
                )
                assertTrue(result7.success, "SL-07 precommit should succeed: ${result7.output}")
                assertTrue(result7.txnId != null && result7.txnId > 0, "Should have valid txnId")
                logger.info("SL-07 precommit succeeded, txnId: ${result7.txnId}")

                def commitResult = execute2PCAction(
                    user: "${testUserBase}_7",
                    password: testPassword,
                    txnId: result7.txnId,
                    action: "commit",
                    certPath: sanClientCert,
                    keyPath: sanClientKey
                )
                assertTrue(commitResult.success, "SL-07 commit should succeed: ${commitResult.output}")
                logger.info("SL-07 PASSED")

                def count7 = sql "SELECT COUNT(*) FROM ${tableName} WHERE k2 = '2pc_test'"
                assertTrue(count7[0][0] >= 1, "2PC data should be committed")
                sql "TRUNCATE TABLE ${tableName}"

                // ==================================================================================
                // SL-08: ALTER USER add/remove REQUIRE SAN -> dynamic effect
                // ==================================================================================
                logger.info("=== SL-08: ALTER USER add/remove REQUIRE SAN ===")
                sql "CREATE USER '${testUserBase}_8'@'%' IDENTIFIED BY '${testPassword}' REQUIRE SAN '${sanFull}'"
                sql "GRANT LOAD_PRIV ON ${context.dbName}.${tableName} TO '${testUserBase}_8'@'%'"

                // 8a: With SAN requirement - should succeed with matching cert
                def result8a = executeStreamLoadCurl(
                    user: "${testUserBase}_8",
                    password: testPassword,
                    table: tableName,
                    data: "9,value9",
                    certPath: sanClientCert,
                    keyPath: sanClientKey
                )
                assertTrue(result8a.success, "SL-08a should succeed: ${result8a.output}")
                logger.info("SL-08a PASSED")
                sql "TRUNCATE TABLE ${tableName}"

                // Remove SAN requirement
                sql "ALTER USER '${testUserBase}_8'@'%' REQUIRE NONE"
                logger.info("Removed REQUIRE SAN")

                // 8b: After REQUIRE NONE - should succeed with no-SAN certificate
                def result8b = executeStreamLoadCurl(
                    user: "${testUserBase}_8",
                    password: testPassword,
                    table: tableName,
                    data: "10,value10",
                    certPath: noSanClientCert,
                    keyPath: noSanClientKey
                )
                assertTrue(result8b.success, "SL-08b should succeed: ${result8b.output}")
                logger.info("SL-08b PASSED")

                // Add back SAN requirement
                sql "ALTER USER '${testUserBase}_8'@'%' REQUIRE SAN '${sanFull}'"
                logger.info("Re-added REQUIRE SAN")
                sql "TRUNCATE TABLE ${tableName}"

                // 8c: After re-adding REQUIRE SAN - no-SAN cert should fail
                def result8c = executeStreamLoadCurl(
                    user: "${testUserBase}_8",
                    password: testPassword,
                    table: tableName,
                    data: "11,value11",
                    certPath: noSanClientCert,
                    keyPath: noSanClientKey
                )
                assertFalse(result8c.success, "SL-08c should fail: REQUIRE SAN re-added")
                logger.info("SL-08c PASSED")

                logger.info("SL-08 PASSED")

                logger.info("=== All Stream Load certificate-based auth tests PASSED ===")

            } finally {
                try {
                    sql "ADMIN SET FRONTEND CONFIG ('tls_cert_based_auth_ignore_password' = '${origIgnorePassword}')"
                } catch (Exception e) {
                    logger.warn("Failed to restore config: ${e.message}")
                }
                cleanup()
            }
        }
    }
}
