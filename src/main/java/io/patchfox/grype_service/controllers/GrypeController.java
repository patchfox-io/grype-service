package io.patchfox.grype_service.controllers;

import java.io.IOException;
import java.time.ZonedDateTime;
import java.util.Optional;
import java.util.UUID;
import java.util.zip.DataFormatException;

import org.apache.catalina.connector.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.patchfox.grype_service.helpers.DbHelper;
import io.patchfox.grype_service.repositories.DatasourceEventRepository;
import io.patchfox.grype_service.services.GrypeService;
import io.patchfox.grype_service.services.HealthCheckService;
import io.patchfox.package_utils.data.pkg.PackageData;
import io.patchfox.package_utils.data.pkg.PackageWrapper;
import io.patchfox.package_utils.json.ApiResponse;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
public class GrypeController {
    
    public static final String API_PATH_PREFIX = "/api/v1";
    public static final String GRYPE_PATH = API_PATH_PREFIX + "/grype";
    public static final String POST_GRYPE_SIGNATURE = "POST_" + GRYPE_PATH;

    @Autowired
    GrypeService grypeService;
    
    @Autowired
    DatasourceEventRepository datasourceEventRepository;

    @PostMapping(
        value = GRYPE_PATH,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    ResponseEntity<ApiResponse> grypeHandler(
        @RequestAttribute UUID txid,
        @RequestAttribute ZonedDateTime requestReceivedAt,
        //@RequestBody PackageWrapper packageWrapper,
        @RequestParam Long datasourceEventRecordId,
        //@RequestParam(defaultValue = "false") boolean recordResults,
        @RequestParam(required = false) Optional<UUID> altTxid
    ) throws IOException, InterruptedException, DataFormatException {

        var datasourceEventRecordOptional = datasourceEventRepository.findById(datasourceEventRecordId);

        if ( datasourceEventRecordOptional.isEmpty() ) {
            var apiResponse = ApiResponse.builder()
                                         .code(Response.SC_BAD_REQUEST)
                                         .serverMessage("datasourceEventRecordId does not exist")
                                         .build();

            return ResponseEntity.status(apiResponse.getCode()).body(apiResponse);
        }

        var datasourceEventRecord = datasourceEventRecordOptional.get();
        var packageWrapperBytes = datasourceEventRecord.getPayload();
        var mapper = new ObjectMapper().findAndRegisterModules();
        var packageWrapper = mapper.readValue(packageWrapperBytes, PackageWrapper.class);

        if ( !packageWrapper.getDependencyData().containsKey(PackageData.PackageDataType.SBOM) ) {
            log.warn("missing expected SBOM package data");
            var apiResponse = ApiResponse.builder()
                                         .code(Response.SC_BAD_REQUEST)
                                         .serverMessage("missing SBOM PackageData")
                                         .build();

            return ResponseEntity.status(apiResponse.getCode()).body(apiResponse);
        }


        var apiResponse = 
            grypeService.enrichWithGrypeOssPackageData(
                txid, 
                requestReceivedAt, 
                datasourceEventRecord,
                packageWrapper, 
                altTxid
            );

        return ResponseEntity.status(apiResponse.getCode()).body(apiResponse);
    }

}
