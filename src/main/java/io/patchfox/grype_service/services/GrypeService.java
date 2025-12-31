package io.patchfox.grype_service.services;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.apache.catalina.connector.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.stereotype.Service;

import io.patchfox.db_entities.entities.Datasource;
import io.patchfox.db_entities.entities.DatasourceEvent;
import io.patchfox.grype_service.components.EnvironmentComponent;
import io.patchfox.grype_service.repositories.DatasourceEventRepository;
import io.patchfox.grype_service.repositories.DatasourceRepository;
import io.patchfox.grype_service.repositories.FindingDataRepository;
import io.patchfox.grype_service.repositories.FindingRepository;
import io.patchfox.grype_service.repositories.PackageRepository;
import io.patchfox.package_utils.data.DataFile;
import io.patchfox.package_utils.data.oss.OssSummary;
import io.patchfox.package_utils.data.oss.anchore.grype.GrypeOssReportPackageData;
import io.patchfox.package_utils.data.pkg.PackageData;
import io.patchfox.package_utils.data.pkg.PackageData.PackageDataType;
import io.patchfox.package_utils.data.pkg.PackageWrapper;
import io.patchfox.package_utils.data.sbom.SbomPackageData;
import io.patchfox.package_utils.json.ApiResponse;
import io.patchfox.package_utils.util.FileHelpers;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Service
public class GrypeService {

    @PersistenceContext
    private EntityManager entityManager;

    @Autowired
    EnvironmentComponent env;

    @Autowired
    private Jackson2ObjectMapperBuilder mapperBuilder;

    @Autowired
    FindingRepository findingRepository;

    @Autowired
    FindingDataRepository findingDataRepository;

    @Autowired
    PackageRepository packageRepository;

    @Autowired
    DatasourceEventRepository datasourceEventRepository;

    @Autowired
    DatasourceRepository datasourceRepository;

    public ApiResponse enrichWithGrypeOssPackageData(
            UUID txid,
            ZonedDateTime requestReceivedAt,
            DatasourceEvent datasourceEventRecord,
            PackageWrapper packageWrapper,
            Optional<UUID> altTxid
    ) throws IOException, InterruptedException {

        // 
        var sbomPackageDataList = packageWrapper.getDependencyData().get(PackageData.PackageDataType.SBOM);
        var sbomPackageData = (SbomPackageData)sbomPackageDataList.get(0);
        var mapper = mapperBuilder.build();

        var sbomBytes = mapper.writeValueAsBytes(sbomPackageData.getData());
        var inputStream = new ByteArrayInputStream(sbomBytes);
        var sbomFileName = UUID.randomUUID().toString() + "_SBOM";
        var grypeFileName = DataFile.DataFileTypeEnum.GRYPE_OSS.getFileName();
        
        //
        var locationPair = FileHelpers.safeSerializeFile(sbomFileName, inputStream);
        var serializeToPath = locationPair.getLeft();
        var serializeToFilePath = locationPair.getRight();

        //
        var rv = ApiResponse.builder()
                            .txid(txid)
                            .requestReceivedAt(requestReceivedAt)
                            .code(Response.SC_INTERNAL_SERVER_ERROR)
                            .data(Map.of("datasourceEventRecordId", datasourceEventRecord.getId()))
                            .build();

        ProcessBuilder processBuilder = new ProcessBuilder();
        processBuilder.command(
            "sh", 
            "-c", 
            "grype --by-cve sbom:" + serializeToFilePath + " -o json > " + serializeToPath.resolve(grypeFileName)
        );

        // log.info("sbom is: {}", sbomPackageData.getData());
        var start = Instant.now();
        Process process = null;
        try {
            process = processBuilder.start();
            int rc = process.waitFor();
            var grypeDone = Instant.now();
            log.info("grype duration: {}", Duration.between(start, grypeDone));
            if (rc == 0) {
                var grypeFile = serializeToPath.resolve(grypeFileName).toFile();
                var dataFile = new DataFile(grypeFile);
                var grypePackageData = (GrypeOssReportPackageData)dataFile.process().get();
                packageWrapper.addDepenencyData(PackageDataType.OSS_REPORT, grypePackageData);
                    
                @SuppressWarnings("unchecked")
                var ossSummaries = (List<OssSummary>)(Object)grypePackageData.getOssDependencyData()
                                                                             .stream()
                                                                             .map(x -> x.getData())
                                                                             .toList();

                for (var ossSummary : ossSummaries) {
                    findingRepository.storeFindingData(
                        setToSqlArrayString(ossSummary.getReporters()), 
                        setToSqlArrayString(ossSummary.getCpes()), 
                        ossSummary.getDescription(), 
                        ossSummary.getVulnerabilityId(), 
                        setToSqlArrayString(ossSummary.getFixedIn()), 
                        requestReceivedAt, 
                        ossSummary.getSeverity().toString(), 
                        ossSummary.getPurl().getCoordinates(),
                        ","
                    );

                    // this shouldn't fucking be necessary given this is a stored proc but w/o it memory blows up 
                    // because fuck hibernate in its stupid fucking face 

                    Runtime runtime = Runtime.getRuntime();
                    long usedMemory = runtime.totalMemory() - runtime.freeMemory();
                    log.info("After processing {} finding java used memory is: {} MB", ossSummary.getVulnerabilityId(), usedMemory / 1024 / 1024);
        
                    // flush hibernate bullshit
                    entityManager.clear();
                    packageRepository.flush();
                    findingRepository.flush();
                    findingDataRepository.flush();

                }

                // jik 
                System.gc();

                var serializeFindingsToDbDone = Instant.now();
                log.info("serializeFindingsToDb duration: {}", Duration.between(grypeDone, serializeFindingsToDbDone));

                // remember -- the txid passed to this service may be the jobId of a pipeline job this service 
                // is being invoked to support. In that case the txid passed to the controller is the jobId of that 
                // pipeline job. Here we need the txid of the transaction that submitted the event for processing
                var datasourceEventTxid = altTxid.isPresent() ? altTxid.get() : txid;
                log.info("txid: {}  altTxid: {}  datasourceEventTxid: {}", txid, altTxid, datasourceEventTxid);

                //datasourceEventRecord.setOssEnriched(true);
                datasourceEventRecord.setPayload(mapperBuilder.build().writeValueAsBytes(packageWrapper));
                //datasourceEventRecord.setStatus(DatasourceEvent.Status.READY_FOR_NEXT_PROCESSING);
                datasourceEventRecord = datasourceEventRepository.save(datasourceEventRecord);
                datasourceEventRepository.flush();

                // because the way hibernate updates these records it can stomp on the status flag setting
                // of another enrichment service by way of race condition 
                datasourceEventRepository.setStatusFlagsFor(datasourceEventRecord.getId());

                var updateDatasourceEventRecordDone = Instant.now();
                log.info("updateDatasourceEventRecordDone duration: {}", Duration.between(serializeFindingsToDbDone, updateDatasourceEventRecordDone));

                rv.setCode(Response.SC_OK);
            } else {
                log.warn("something went wrong running grype. received non-zero response code: {}", rc);
            }
        } catch (Exception e) {
            log.error("caught unexpected exception:", e);
            rv.setServerMessage(
                String.format(
                    "unexpected exception: %s for event txid: %s", 
                    e.getClass().getName(),
                    altTxid.isPresent() ? altTxid.get() : txid
                )
            );
            // this should not be necessary but I'm seeing this catch being tripped and no associated error response
            // in orchestrate-service logs 
            rv.setCode(Response.SC_INTERNAL_SERVER_ERROR);
            datasourceEventRecord.setStatus(DatasourceEvent.Status.PROCESSING_ERROR);
            datasourceEventRecord = datasourceEventRepository.save(datasourceEventRecord);

            var datasource = datasourceEventRecord.getDatasource();
            datasource.setStatus(Datasource.Status.PROCESSING_ERROR);
            datasource = datasourceRepository.save(datasource);

            datasourceEventRecord.setStatus(DatasourceEvent.Status.PROCESSING_ERROR);
            datasourceEventRepository.save(datasourceEventRecord);
            datasourceEventRepository.flush();
        } finally {
            FileHelpers.safeDeletePath(locationPair.getLeft());
            if (process != null) { 
                process.descendants().forEach(ProcessHandle::destroy);
                process.destroy(); 
            }

            var allDone = Instant.now();
            log.info("total duration: {}", Duration.between(start, allDone));
        }

        return rv;

    }

    public String setToSqlArrayString(Set<String> s) {
        return s.toString()
                .replace("[", "")
                .replace("]", "")
                .replace(" ", "");
    }
}
