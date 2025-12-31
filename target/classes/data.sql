-- CREATE OR REPLACE FUNCTION STORE_FINDING_DATA(
--     finding_reporters_arg_str_encoded_array varchar,
--     cpes_arg_str_encoded_array varchar, 
--     description_arg varchar, 
--     identifier_arg varchar, 
--     patched_in_arg_str_encoded_array varchar, 
--     reported_at_arg timestamptz, 
--     severity_arg varchar,
--     purl_arg varchar,
--     array_delimiter_arg varchar
-- ) 
-- RETURNS void
-- AS '
-- DECLARE
--     finding_pk bigint;
--     finding_reporter_pk bigint;
--     package_pk bigint;
--     finding_reporters_arg varchar[];
--     cpes_arg varchar[];
--     patched_in_arg varchar[];
-- BEGIN
--     -- convert string_array args to array type
--     SELECT string_to_array(finding_reporters_arg_str_encoded_array::text, array_delimiter_arg::text) INTO finding_reporters_arg;
--     SELECT string_to_array(cpes_arg_str_encoded_array::text, array_delimiter_arg::text) INTO cpes_arg;
--     SELECT string_to_array(patched_in_arg_str_encoded_array::text, array_delimiter_arg::text) INTO patched_in_arg;		
    
--     -- create finding_reporter records if they do not already exist 
--     FOR index IN 1..array_length(finding_reporters_arg, 1) LOOP
--         INSERT 
--             INTO finding_reporter (name) 
--             VALUES (finding_reporters_arg[index])
--             ON CONFLICT DO NOTHING;
--     END LOOP;
    
--     -- create finding_data record if it does not already exist 
--     INSERT 
--         INTO finding_data (cpes, description, identifier, patched_in, reported_at, severity) 
--         VALUES (
--             cpes_arg, 
--             description_arg, 
--             identifier_arg,
--             patched_in_arg,
--             reported_at_arg,
--             severity_arg
--         )
--         ON CONFLICT DO NOTHING;
        
--     -- create finding record if it does not already exist
--     INSERT 
--         INTO finding (identifier) 
--         VALUES (identifier_arg)
--         ON CONFLICT DO NOTHING;
        
--     -- create association between finding and finding_data records
--     SELECT id 
--         FROM finding f 
--         INTO finding_pk 
--         WHERE f.identifier = identifier_arg;
--     UPDATE finding_data fd 
--         SET finding_id = finding_pk 
--         WHERE fd.identifier = identifier_arg; 
        
--     -- create assocation between finding and reporter records 
--     FOR index IN 1..array_length(finding_reporters_arg, 1) LOOP
--         SELECT id 
--             FROM finding_reporter fr
--             INTO finding_reporter_pk
--             WHERE fr.name = finding_reporters_arg[index];
--         INSERT 
--             INTO finding_to_reporter (finding_id, reporter_id)
--             VALUES (finding_pk, finding_reporter_pk)
--             ON CONFLICT DO NOTHING;
--     END LOOP;
    
--     -- create association between package and finding (original index table)
--     SELECT id
--         FROM package p
--         INTO package_pk
--         WHERE p.purl = purl_arg;
--     INSERT
--         INTO package_finding (package_id, finding_id)
--         VALUES (package_pk, finding_pk)
--         ON CONFLICT DO NOTHING;
        
--     -- create associations in severity-specific index tables
--     IF package_pk IS NOT NULL AND finding_pk IS NOT NULL THEN
--         IF severity_arg = ''CRITICAL'' THEN
--             INSERT INTO package_critical_finding (package_id, finding_id)
--             VALUES (package_pk, finding_pk)
--             ON CONFLICT DO NOTHING;
--         ELSIF severity_arg = ''HIGH'' THEN
--             INSERT INTO package_high_finding (package_id, finding_id)
--             VALUES (package_pk, finding_pk)
--             ON CONFLICT DO NOTHING;
--         ELSIF severity_arg = ''MEDIUM'' THEN
--             INSERT INTO package_medium_finding (package_id, finding_id)
--             VALUES (package_pk, finding_pk)
--             ON CONFLICT DO NOTHING;
--         ELSIF severity_arg = ''LOW'' THEN
--             INSERT INTO package_low_finding (package_id, finding_id)
--             VALUES (package_pk, finding_pk)
--             ON CONFLICT DO NOTHING;
--         ELSE
--             RAISE NOTICE ''Unexpected severity value: %. Skipping severity-specific index.'', severity_arg;
--         END IF;
--     END IF;
    
-- END;
-- ' LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION STORE_FINDING_DATA(
    finding_reporters_arg_str_encoded_array varchar,
    cpes_arg_str_encoded_array varchar, 
    description_arg varchar, 
    identifier_arg varchar, 
    patched_in_arg_str_encoded_array varchar, 
    reported_at_arg timestamptz, 
    severity_arg varchar,
    purl_arg varchar,
    array_delimiter_arg varchar
) 
RETURNS void
AS '
DECLARE
    finding_reporters_arg varchar[];
    cpes_arg varchar[];
    patched_in_arg varchar[];
    finding_pk bigint;
    package_pk bigint;
BEGIN
    -- Convert string arrays to array type
    finding_reporters_arg := string_to_array(finding_reporters_arg_str_encoded_array, array_delimiter_arg);
    cpes_arg := string_to_array(cpes_arg_str_encoded_array, array_delimiter_arg);
    patched_in_arg := string_to_array(patched_in_arg_str_encoded_array, array_delimiter_arg);

    -- Step 1: Bulk insert finding_reporters (avoid loop)
    INSERT INTO finding_reporter (name) 
    SELECT DISTINCT unnest(finding_reporters_arg)
    ON CONFLICT DO NOTHING;

    -- Step 2: Insert finding if it does not exist and get ID
    INSERT INTO finding (identifier) 
    VALUES (identifier_arg)
    ON CONFLICT (identifier) DO NOTHING;
    
    SELECT id INTO finding_pk FROM finding WHERE identifier = identifier_arg;

    -- Step 3: Insert finding_data with finding_id
    INSERT INTO finding_data (cpes, description, identifier, patched_in, reported_at, severity, finding_id) 
    VALUES (
        cpes_arg, 
        description_arg, 
        identifier_arg,
        patched_in_arg,
        reported_at_arg,
        severity_arg,
        finding_pk
    )
    ON CONFLICT (identifier) DO UPDATE SET finding_id = EXCLUDED.finding_id;

    -- Step 4: Bulk insert finding to reporter relationships
    INSERT INTO finding_to_reporter (finding_id, reporter_id)
    SELECT finding_pk, fr.id
    FROM finding_reporter fr 
    WHERE fr.name = ANY(finding_reporters_arg)
    ON CONFLICT DO NOTHING;

    -- Step 5: Get package ID and insert package_finding relationship
    SELECT id INTO package_pk FROM package WHERE purl = purl_arg;
    
    IF package_pk IS NOT NULL THEN
        INSERT INTO package_finding (package_id, finding_id)
        VALUES (package_pk, finding_pk)
        ON CONFLICT DO NOTHING;

        -- Step 6: Insert into appropriate severity table
        IF severity_arg = ''CRITICAL'' THEN
            INSERT INTO package_critical_finding (package_id, finding_id)
            VALUES (package_pk, finding_pk)
            ON CONFLICT DO NOTHING;
        ELSEIF severity_arg = ''HIGH'' THEN
            INSERT INTO package_high_finding (package_id, finding_id)
            VALUES (package_pk, finding_pk)
            ON CONFLICT DO NOTHING;
        ELSEIF severity_arg = ''MEDIUM'' THEN
            INSERT INTO package_medium_finding (package_id, finding_id)
            VALUES (package_pk, finding_pk)
            ON CONFLICT DO NOTHING;
        ELSEIF severity_arg = ''LOW'' THEN
            INSERT INTO package_low_finding (package_id, finding_id)
            VALUES (package_pk, finding_pk)
            ON CONFLICT DO NOTHING;
        ELSE
            RAISE NOTICE ''Unexpected severity value: %. Skipping severity-specific index.'', severity_arg;
        END IF;
    END IF;

END;
' LANGUAGE plpgsql;
