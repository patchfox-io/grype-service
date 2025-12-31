package io.patchfox.grype_service.repositories;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import io.patchfox.db_entities.entities.DatasourceEvent;
import jakarta.transaction.Transactional;

public interface DatasourceEventRepository extends JpaRepository<DatasourceEvent, Long> {
    List<DatasourceEvent> findAllByTxid(UUID txid);

    @Modifying
    @Transactional
    @Query(
        value = "UPDATE datasource_event " +
	            "SET oss_enriched = true, status = 'READY_FOR_NEXT_PROCESSING' " +
	            "WHERE id = ?1 ",

        nativeQuery = true
    )
    void setStatusFlagsFor(Long id);
}
