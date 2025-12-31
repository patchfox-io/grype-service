package io.patchfox.grype_service.scheduled;


import java.io.IOException;
import java.util.concurrent.TimeUnit;

import org.springframework.scheduling.annotation.Scheduled;

import lombok.extern.slf4j.Slf4j;


@Slf4j
public class ScheduledTasks {

    @Scheduled(fixedDelay = 60, timeUnit = TimeUnit.MINUTES)
    public void checkGrypeDbUpdate() {
        log.info("checking grype db for updates");

        ProcessBuilder processBuilder = new ProcessBuilder();
        processBuilder.command(
            "sh", 
            "-c", 
            "grype db update"
        );

        Process process = null;
        try {
            process = processBuilder.start();
            int rc = process.waitFor();
            if (rc == 0) {
                log.info("db successfully updated");
            } else {
                log.warn("something went wrong updating grype. received non-zero response code: {}", rc);
            }
        } catch (IOException | InterruptedException e) {
            log.error("caught unexpected exception while attempting to update grype db", e);
        } finally {
            if (process != null) { 
                process.descendants().forEach(ProcessHandle::destroy);
                process.destroy(); 
            }
        }
         
    }

}
