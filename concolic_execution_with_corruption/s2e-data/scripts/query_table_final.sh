#!/bin/bash

echo "CACHE NAME | OBJ PER CACHE | NO PANIC | #DIFFERENT | # NO CONST COUNTERFEIT | # NO CONST ATTACKBUF | # NO CONST ENTRY BUF "

sqlite3 /home/s2e/cco_s2e/projects/kdo_final_results.sql  <<'EOF'
SELECT
    kdo_obj_cache,
    COUNT(*),
    SUM(CASE WHEN panic = 0 THEN 1 ELSE 0 END) as count_no_panic,
    SUM(CASE type_syscall WHEN 'different' THEN 1 ELSE 0 END) as count_different,
    SUM(CASE WHEN counterfeit_memop = 0 THEN 1 ELSE 0 END) as count_no_constraints_countefeit,
    SUM(CASE WHEN attacker_buf_memop = 0 THEN 1 ELSE 0 END) as count_no_constraints_attacker_buf,
    SUM(CASE WHEN kdo_object_entry_memop = 0 THEN 1 ELSE 0 END) as count_no_constraints_kdo_object_entry
    FROM records  WHERE memop_signal=1 GROUP BY kdo_obj_cache ORDER BY kdo_obj_cache;
EOF


echo "TOTAL OBJECTS"
sqlite3 /home/s2e/cco_s2e/projects/kdo_final_results.sql  <<'EOF'
SELECT
    COUNT(*)
    FROM records
    WHERE memop_signal=1
EOF

echo "TOTAL NO PANIC"
sqlite3 /home/s2e/cco_s2e/projects/kdo_final_results.sql  <<'EOF'
SELECT
    SUM(CASE WHEN panic = 0 THEN 1 ELSE 0 END) as count_no_panic
    FROM records
    WHERE memop_signal=1
EOF

echo "TOTAL DIFFERENT SYSCALL"
sqlite3 /home/s2e/cco_s2e/projects/kdo_final_results.sql  <<'EOF'
SELECT
    SUM(CASE type_syscall WHEN 'different' THEN 1 ELSE 0 END) as count_different
    FROM records
    WHERE memop_signal=1
EOF

echo "TOTAL NO COUNTERFEIT CONSTRAINTS"
sqlite3 /home/s2e/cco_s2e/projects/kdo_final_results.sql  <<'EOF'
SELECT
    SUM(CASE WHEN counterfeit_memop = 0 THEN 1 ELSE 0 END) as count_no_constraints_countefeit
    FROM records
    WHERE memop_signal=1
EOF

echo "TOTAL NO ATTACKER BUF CONSTRAINTS"
sqlite3 /home/s2e/cco_s2e/projects/kdo_final_results.sql  <<'EOF'
SELECT
    SUM(CASE WHEN attacker_buf_memop = 0 THEN 1 ELSE 0 END) as count_no_constraints_attacker_buf
    FROM records
    WHERE memop_signal=1
EOF

echo "TOTAL NO KDO_OBJECT_ENTRY CONSTRAINTS"
sqlite3 /home/s2e/cco_s2e/projects/kdo_final_results.sql  <<'EOF'
SELECT
    SUM(CASE WHEN kdo_object_entry_memop = 0 THEN 1 ELSE 0 END) as count_no_constraints_kdo_object_entry
    FROM records
    WHERE memop_signal=1
EOF

echo "OBJ WITH O constraints"
sqlite3 /home/s2e/cco_s2e/projects/kdo_final_results.sql  <<'EOF'
SELECT
    *
    FROM records
    WHERE memop_signal=1 and counterfeit_memop = 0 and attacker_buf_memop = 0 and kdo_object_entry_memop = 0
EOF

echo "Large Table"
echo "ID & TYPE & # COUNTERFEIT MEMOP & ATTACKER_BUF MEMOP & OBJ ENTRY MEMOP & COUTERFEIT RETURN & ATTACKER_BUF RETURN & OBJ ENTRY RETURN"
sqlite3 /home/s2e/cco_s2e/projects/kdo_final_results.sql <<'EOF'
SELECT
    record_id, kdo_obj_cache, type_syscall, counterfeit_memop, attacker_buf_memop, kdo_object_entry_memop, counterfeit_return, attacker_buf_return, kdo_object_entry_return
    FROM records
    WHERE memop_signal=1 and panic = 0
    ORDER BY type_syscall, record_id ASC
EOF
echo "SPLIT PANIC"
sqlite3 /home/s2e/cco_s2e/projects/kdo_final_results.sql <<'EOF'
SELECT
    record_id, kdo_obj_cache, type_syscall, counterfeit_memop, attacker_buf_memop, kdo_object_entry_memop, counterfeit_return, attacker_buf_return, kdo_object_entry_return
    FROM records
    WHERE memop_signal=1 and panic = 1
    ORDER BY type_syscall, record_id ASC
EOF
