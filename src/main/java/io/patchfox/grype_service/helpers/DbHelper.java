package io.patchfox.grype_service.helpers;


import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.HashSet;
import java.io.IOException;
import java.time.ZonedDateTime;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.core.JsonProcessingException;

import io.patchfox.db_entities.entities.Datasource;
import io.patchfox.db_entities.entities.DatasourceEvent;
import io.patchfox.db_entities.entities.Finding;
import io.patchfox.db_entities.entities.FindingData;
import io.patchfox.db_entities.entities.FindingReporter;
import io.patchfox.db_entities.entities.Package;
import io.patchfox.grype_service.repositories.DatasourceEventRepository;
import io.patchfox.grype_service.repositories.DatasourceRepository;
import io.patchfox.grype_service.repositories.FindingDataRepository;
import io.patchfox.grype_service.repositories.FindingReporterRepository;
import io.patchfox.grype_service.repositories.FindingRepository;
import io.patchfox.grype_service.repositories.PackageRepository;
import io.patchfox.package_utils.data.oss.OssSummary;
import io.patchfox.package_utils.data.oss.anchore.grype.GrypeOssReportPackageData;
import io.patchfox.package_utils.data.pkg.PackageData;
import io.patchfox.package_utils.data.pkg.PackageWrapper;

import lombok.extern.slf4j.Slf4j;


@Slf4j
@Component
public class DbHelper {
    
    @Autowired
    DatasourceEventRepository datasourceEventRepository;

    @Autowired
    DatasourceRepository datasourceRepository;

    @Autowired
    FindingRepository findingRepository;

    @Autowired
    FindingReporterRepository findingReporterRepository;

    @Autowired
    FindingDataRepository findingDataRepository;

    @Autowired
    PackageRepository packageRepository;

    @Autowired
    private Jackson2ObjectMapperBuilder mapperBuilder;


    // /**
    //  * 
    //  * @param txid
    //  */
    // public void updateDatasourceEventRecordWithError(UUID txid) {
    //     List<DatasourceEvent> datasourceEvents = datasourceEventRepository.findAllByTxid(txid);
    //     if (datasourceEvents.size() != 1) {
    //         log.error(
    //             "expected one datasource event record in the database for txid: {} but found : {}",
    //             txid,
    //             datasourceEvents.size()
    //         );

    //         // will result in an API repsonse with a 500 error...
    //         throw new IllegalStateException();
    //     }

    //     var datasourceEvent = datasourceEvents.get(0);
    //     datasourceEvent.setStatus(DatasourceEvent.Status.PROCESSING_ERROR);
    //     datasourceEventRepository.save(datasourceEvent);

    //     var datasource = datasourceEvent.getDatasource();
    //     datasource.setStatus(Datasource.Status.PROCESSING_ERROR);
    //     datasourceRepository.save(datasource);

    //     return;        
    // }


    // /**
    //  * 
    //  * @param txid
    //  * @throws IOException 
    //  * @throws JsonProcessingException 
    //  */
    // public void updateDatasourceEventRecord(
    //         DatasourceEvent datasourceEventRecord,
    //         PackageWrapper p
    //         //UUID txid
    // ) throws IllegalStateException, JsonProcessingException, IOException {

    //     // List<DatasourceEvent> datasourceEvents = datasourceEventRepository.findAllByTxid(txid);
    //     // if (datasourceEvents.size() != 1) {
    //     //     log.error(
    //     //         "expected one datasource event record in the database for txid: {} but found : {}",
    //     //         txid,
    //     //         datasourceEvents.size()
    //     //     );

    //     //     // will result in an API repsonse with a 500 error...
    //     //     throw new IllegalStateException();
    //     // }

    //     // var datasourceEvent = datasourceEvents.get(0);
    //     datasourceEventRecord.setOssEnriched(true);
    //     datasourceEventRecord.setPayload(mapperBuilder.build().writeValueAsBytes(p));
    //     datasourceEventRecord.setStatus(DatasourceEvent.Status.READY_FOR_NEXT_PROCESSING);
    //     datasourceEventRepository.save(datasourceEventRecord);
    //     return;
    // }



    // /**
    //  * 
    //  * @param findingReporters
    //  * @param packageRecord
    //  * @param findingDataRecord
    //  * @return
    //  */
    // @Synchronized
    // public Finding fetchOrMakeAndFetchFindingRecord(
    //     Set<FindingReporter> findingReporters,
    //     Package packageRecord,
    //     FindingData findingDataRecord
    // ) {

    //     var findingRecord = Finding.builder()
    //                                .reporters(findingReporters)
    //                                .packages(new HashSet<>(Set.of(packageRecord)))
    //                                .data(findingDataRecord)
    //                                .build();

    //     var findings = findingRepository.findAllByDataIdentifier(findingDataRecord.getIdentifier());
    //     if (findings.isEmpty() == false) { return findings.get(0); }

    //     findingRecord = findingRepository.save(findingRecord);
    //     findingDataRecord.setFinding(findingRecord);
    //     findingDataRecord = findingDataRepository.save(findingDataRecord);

    //     packageRecord.getFindings().add(findingRecord);
    //     packageRecord = packageRepository.save(packageRecord);

    //     for (var findingReporterRecord : findingReporters) {
    //         findingReporterRecord.getFindings().add(findingRecord);
    //         findingReporterRepository.save(findingReporterRecord);   
    //     }

    //     return findingRecord;
    // }


    /**
     * 
     * @param reporterName
     * @return
     */
    @Transactional(isolation = Isolation.SERIALIZABLE)
    //@Synchronized
    public FindingReporter fetchOrMakeAndFetchFindingReporterRecord(String reporterName) {

        var findingReporterRecords = findingReporterRepository.findByName(reporterName);
        // TODO you really need to create a common validator for this ...
        if (findingReporterRecords.size() > 1) {
            log.error(
                "something has gone very wrong. reporter record name field {} should be " + 
                "unique but record count is: {}. system integrity compromised. " +
                "throwing exception...",
                reporterName,
                findingReporterRecords.size()
            );      

            throw new IllegalStateException();
        } else if (findingReporterRecords.size() == 1) {
            return findingReporterRecords.get(0);
        } else {
            var findingReporterRecord = FindingReporter.builder()
                                                       .name(reporterName)
                                                       .build();

            // there is ocassionally a race condition where one thread is able to create the record between the time 
            // this thread checks to see if one exists and - if one doesn't - attempts to make it. 
            // @Transactional annotation did not work 
            // @Syncronized created a slow but persistent memory leak                      
            try {
                return findingReporterRepository.save(findingReporterRecord);
            } catch (DataIntegrityViolationException e) {
                return findingReporterRepository.findByName(reporterName).get(0);
            }
            
        }
                    
    }



    // /**
    //  * 
    //  * @param ossSummary
    //  * @param requestReceivedAt
    //  * @return
    //  * @throws InterruptedException 
    //  */
    // @Transactional(isolation = Isolation.SERIALIZABLE)
    // //@Synchronized
    // public FindingData fetchOrMakeAndFetchFindingDataRecord(
    //         OssSummary ossSummary, 
    //         ZonedDateTime requestReceivedAt, 
    //         Set<FindingReporter> findingReporters
    // ) throws InterruptedException {

    //     // check to see if record already exists. if it does use that one 
    //     var findingDataRecords = findingDataRepository.findByIdentifier(ossSummary.getVulnerabilityId());

    //     // TODO same here - made a common validator for this 
    //     if (findingDataRecords.size() > 1) {
    //         log.error(
    //             "something went very wrong. FindingData.identifier should be unique in database " +
    //             "and is not. received {} records for same identifier {}. System integrity " +
    //             "may be compromised. Throwing exception...",
    //             findingDataRecords.size(),
    //             ossSummary.getVulnerabilityId()
    //         );

    //         throw new IllegalStateException();
    //     } else if (findingDataRecords.size() == 1) {
    //         return findingDataRecords.get(0);
    //     } else {
    //         return makeNewFindingDataRecord(ossSummary, requestReceivedAt, findingReporters); 
    //     }
    // }


    // /**
    //  * 
    //  * @param ossSummary
    //  * @param requestReceivedAt
    //  * @return
    //  * @throws InterruptedException 
    //  */
    // //@Synchronized
    // @Transactional(isolation = Isolation.SERIALIZABLE)
    // private FindingData makeNewFindingDataRecord(
    //         OssSummary ossSummary, 
    //         ZonedDateTime requestReceivedAt, 
    //         Set<FindingReporter> findingReporters
    // ) throws DataIntegrityViolationException {

    //     var findingDataRecord = FindingData.builder()
    //                                        .identifier(ossSummary.getVulnerabilityId())
    //                                        .severity(ossSummary.getSeverity().toString())
    //                                        .description(ossSummary.getDescription())
    //                                        .cpes(ossSummary.getCpes())
    //                                        .patchedIn(ossSummary.getFixedIn())
    //                                        .reportedAt(requestReceivedAt)
    //                                        .build();

    //     try {
    //         // TODO - this will catch the race condition where two or more callers end up here - but there should be
    //         // a db lock that can handle this or some better way... 
    //         // also - we don't want to add @Synchronized to this call because under load the thread wait times stack 
    //         // as they all try to enter the @Sychronized method and it creates backpressure. 
    //         return findingDataRepository.save(findingDataRecord);
    //     } catch (DataIntegrityViolationException e) {
    //         return findingDataRepository.findByIdentifier(ossSummary.getVulnerabilityId()).get(0);
    //     }

    // }

    /**
     * 
     * @param p
     * @param requestReceivedAt
     * @throws InterruptedException 
     */
    // @Synchronized is here to prevent weird db errors caused by race conditions as multiple callers hit this 
    // method at the same time. A better solution is probably to use spring-data @Transactional annotation 
    // see https://docs.spring.io/spring-framework/reference/data-access/transaction.html
    // @Synchronized
    //@Transactional
    public void serializeFindingsToDb(PackageWrapper p, ZonedDateTime requestReceivedAt) throws InterruptedException {

        var packageData = p.getDependencyData();
        for (var ossPackageData : packageData.get(PackageData.PackageDataType.OSS_REPORT)) {
            var grypeOssReportPackageData = (GrypeOssReportPackageData)ossPackageData;
            
            @SuppressWarnings("unchecked")
            var ossSummaries = (List<OssSummary>)(Object)grypeOssReportPackageData.getOssDependencyData()
                                                                                  .stream()
                                                                                  .map(x -> x.getData())
                                                                                  .toList();

            for (var ossSummary : ossSummaries) {

                // //
                // // findingReporter
                // //

                // Set<FindingReporter> findingReporters = new HashSet<>(); 
                // for (var reporterName : ossSummary.getReporters()) {                    
                //     var findingReporter = fetchOrMakeAndFetchFindingReporterRecord(reporterName);
                //     findingReporters.add(findingReporter);
                // }
                
                // //
                // // findingData
                // //

                // //var findingDataRecord = fetchOrMakeAndFetchFindingDataRecord(ossSummary, requestReceivedAt, findingReporters);
                // var findingDataRecord = 
                //     findingDataRepository.fetchOrCreateAndFetchFindingDataRecord(
                //         ossSummary.getCpes(), 
                //         ossSummary.getDescription(),
                //         ossSummary.getVulnerabilityId(),
                //         ossSummary.getFixedIn(),
                //         requestReceivedAt,
                //         ossSummary.getSeverity().toString()
                //     );

                // // 
                // // finding
                // //

                // // at this point in the flow we are guaranteed to have a package record corresponding 
                // // to this purl. the package table gets updated on receipt of caller payload. we're
                // // now in a callback flow where we're are enriching the data we already have. if 
                // // this blows up something really done did went' wrong. 
                // var purl = ossSummary.getPurl().getCoordinates();

                // var packageRecords = packageRepository.findByPurl(purl);
                // if (packageRecords.isEmpty()) {
                //     log.warn("unexpectedly not able to find packageRecord for purl: {}", purl);
                //     continue;
                // }

                // var packageRecord = packageRecords.get(0);

                // // if finding is null it's because we're looking at the findingData obj we just made and 
                // // not one we made before and stored in the database. 
                // Finding findingRecord = null;
                // if (findingDataRecord.getFinding() == null) {

                //     // // this method is @Synchronized and has a check at the top of the logic looking to the db before
                //     // // creating a new finding record. 
                //     // fetchOrMakeAndFetchFindingRecord(
                //     //     findingReporters, 
                //     //     packageRecord, 
                //     //     findingDataRecord
                //     // );

                //     findingRecord = Finding.builder()
                //                            .reporters(new HashSet<FindingReporter>())
                //                            .packages(new HashSet<Package>())
                //                            .identifier(findingDataRecord.getIdentifier())
                //                            .build();
                    
                //     try {
                //         findingRecord = findingRepository.save(findingRecord);
                //     } catch (DataIntegrityViolationException e) {
                //         findingRecord = findingRepository.findAllByIdentifier(findingDataRecord.getIdentifier()).get(0);
                //     }
                    
                //     findingDataRecord.setFinding(findingRecord);
                //     findingDataRecord = findingDataRepository.save(findingDataRecord);
                //     findingRecord.setData(findingDataRecord);
                //     findingRecord = findingRepository.save(findingRecord);
                // } 
                // // otherwise add to the existing record 
                // else {
                //     findingRecord = findingDataRecord.getFinding();
                // }
                    
                // if ( !findingRecord.getPackages().contains(packageRecord)) {
                //     findingRecord.getPackages().add(packageRecord);
                //     findingRecord = findingRepository.save(findingRecord);

                //     // not sure why this is needed but it happens every once in a while
                //     // TODO fix this along with refactoring all of this to use the db more heavily for the heavy lift 
                //     try {
                //         packageRecord.getFindings().add(findingRecord);
                //         packageRecord = packageRepository.save(packageRecord);
                //     } catch (DataIntegrityViolationException e) {
                //         //noop
                //         // the package/finding relation already exists
                //     }

                    
                // }

                // // 
                // for (var findingReporterRecord : findingReporters) {
                //     if ( !findingRecord.getReporters().contains(findingReporterRecord)) {
                //         findingRecord.getReporters().add(findingReporterRecord);

                //         try {
                //             findingRecord = findingRepository.save(findingRecord);
                //         } catch (DataIntegrityViolationException e) {
                //             // noop - data is already there 
                //         }
                        

                //         findingReporterRecord.getFindings().add(findingRecord);
                //         findingReporterRecord = findingReporterRepository.save(findingReporterRecord);                                        
                //     }
                // }

                //     // no need to add findingData - it's already there 
                // //}

            }
                
        }

    }

}
