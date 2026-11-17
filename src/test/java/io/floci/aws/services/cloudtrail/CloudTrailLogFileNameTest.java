package io.floci.aws.services.cloudtrail;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class CloudTrailLogFileNameTest {

    @Test
    void aLogFileIsNamedAfterTheEndOfItsFiveMinuteSlot() {
        assertThat(CloudTrailLogWriter.endOfSlot(LocalDateTime.of(2026, 11, 17, 21, 51, 44)),
                equalTo(LocalDateTime.of(2026, 11, 17, 21, 55)));
        assertThat(CloudTrailLogWriter.endOfSlot(LocalDateTime.of(2026, 11, 17, 21, 55, 0)),
                equalTo(LocalDateTime.of(2026, 11, 17, 22, 0)));
        assertThat(CloudTrailLogWriter.endOfSlot(LocalDateTime.of(2026, 11, 17, 23, 58, 3)),
                equalTo(LocalDateTime.of(2026, 11, 18, 0, 0)));
    }
}
