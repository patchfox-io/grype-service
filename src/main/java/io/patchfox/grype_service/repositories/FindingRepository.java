package io.patchfox.grype_service.repositories;


import java.time.ZonedDateTime;
import java.util.List;
import java.util.Set;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import io.patchfox.db_entities.entities.Finding;
import jakarta.transaction.Transactional;


public interface FindingRepository extends JpaRepository<Finding, Long> {

    List<Finding> findAllByDataIdentifier(String identifier);

    List<Finding> findAllByIdentifier(String identifier);

    @Transactional
    @Query(
        value = "SELECT STORE_FINDING_DATA(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)", 
        nativeQuery = true
    )
    void storeFindingData(
        String findingReporters,
        String cpes, 
        String description, 
        String identifier, 
        String patchedIn, 
        ZonedDateTime reportedAt, 
        String severity,
        String purl,
        String arrayDelimiter
    );

}
