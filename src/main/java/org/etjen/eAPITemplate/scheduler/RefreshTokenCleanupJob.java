package org.etjen.eAPITemplate.scheduler;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.etjen.eAPITemplate.repository.RefreshTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class RefreshTokenCleanupJob {
    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenCleanupJob.class);
    private final RefreshTokenRepository refreshTokenRepository;

    @Scheduled(cron = "${data.cleanup.refreshTokensCron}", zone = "UTC")
    @Transactional
    public void purge() {
        try {
            Instant cutoff = Instant.now();
            int rows = refreshTokenRepository.purgeExpiredAndRevoked(cutoff);
            if (rows > 0) {
                logger.info("Refresh-token cleanup removed {} rows (cutoff = {})", rows, cutoff);
            }
        } catch (Exception ex) {
            logger.error("Refresh-token cleanup job failed", ex);
        }
    }
}
