package io.patchfox.grype_service.repositories;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.Set;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import io.patchfox.db_entities.entities.FindingData;
import jakarta.persistence.LockModeType;


public interface FindingDataRepository extends JpaRepository<FindingData, Long> {

    public static final String FETCH_OR_CREATE_AND_FETCH_QUERY = 
        """
        DO
        $$
        BEGIN
            IF 
                NOT EXISTS (SELECT * FROM finding_data fd WHERE fd.identifier = $3)
            THEN
                INSERT 
                    INTO finding_data (cpes, description, identifier, patched_in, reported_at, severity) 
                    VALUES ($1, $2, $3, $4, $5, $6);
            ELSE
                SELECT * FROM finding_data fd WHERE fd.identifier = $3;
            END IF;
        END
        $$   
        """;



    // @Transactional
    // @Lock(LockModeType.PESSIMISTIC_READ)
    List<FindingData> findByIdentifier(String identifier);    

    @Query(
        value = FETCH_OR_CREATE_AND_FETCH_QUERY,
        nativeQuery = true
    )
    FindingData fetchOrCreateAndFetchFindingDataRecord(
        Set<String> cpes,
        String description,
        String identifier,
        Set<String> patchedIn,
        ZonedDateTime reportedAt,
        String severity
    );
    
}


/*

INSERT INTO table_name
VALUES (value1, value2, value3, ...); 

  @Query("select u from User u where u.emailAddress = ?1")
  User findByEmailAddress(String emailAddress);


 *         var findingDataRecord = FindingData.builder()
                                           .identifier(ossSummary.getVulnerabilityId())
                                           .severity(ossSummary.getSeverity().toString())
                                           .description(ossSummary.getDescription())
                                           .cpes(ossSummary.getCpes())
                                           .patchedIn(ossSummary.getFixedIn())
                                           .reportedAt(requestReceivedAt)
                                           .build();
 */