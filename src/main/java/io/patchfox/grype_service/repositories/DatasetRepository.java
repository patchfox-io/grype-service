package io.patchfox.grype_service.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import io.patchfox.db_entities.entities.Dataset;

public interface DatasetRepository extends JpaRepository<Dataset, Long> {}
