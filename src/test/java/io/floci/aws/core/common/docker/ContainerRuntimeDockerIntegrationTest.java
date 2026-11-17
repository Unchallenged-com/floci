package io.floci.aws.core.common.docker;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.InspectContainerResponse;
import com.github.dockerjava.api.exception.NotFoundException;
import io.floci.aws.testing.TestImages;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The Docker runtime a container names is the one the daemon records for it, and a runtime the daemon has not
 * registered fails the create, as {@code docker run --runtime} does.
 */
@QuarkusTest
class ContainerRuntimeDockerIntegrationTest {

    private static final Logger LOG = Logger.getLogger(ContainerRuntimeDockerIntegrationTest.class);
    private static final String IMAGE = TestImages.BUSYBOX;

    @Inject
    DockerClient dockerClient;

    @Inject
    ContainerBuilder containerBuilder;

    @Inject
    ContainerLifecycleManager lifecycleManager;

    @BeforeEach
    void requireDocker() {
        Assumptions.assumeTrue(isDockerAvailable(), "Docker daemon must be available for runtime integration tests");
    }

    @Test
    void theDaemonRecordsTheRuntimeAContainerNames() {
        // runc is the runtime every Docker daemon registers.
        ContainerSpec spec = containerBuilder.newContainer(IMAGE)
                .withName("floci-runtime-test-" + UUID.randomUUID())
                .withCmd(List.of("sleep", "30"))
                .withRuntime("runc")
                .build();

        String containerId = null;
        try {
            containerId = lifecycleManager.create(spec);

            InspectContainerResponse inspect = dockerClient.inspectContainerCmd(containerId).exec();
            assertEquals("runc", inspect.getHostConfig().getRuntime());
        } finally {
            if (containerId != null) {
                dockerClient.removeContainerCmd(containerId).withForce(true).exec();
            }
        }
    }

    @Test
    void aRuntimeTheDaemonDoesNotKnowFailsTheCreate() {
        String name = "floci-runtime-test-" + UUID.randomUUID();
        ContainerSpec spec = containerBuilder.newContainer(IMAGE)
                .withName(name)
                .withCmd(List.of("sleep", "30"))
                .withRuntime("floci-no-such-runtime")
                .build();

        assertThrows(RuntimeException.class, () -> lifecycleManager.create(spec));
        assertThrows(NotFoundException.class, () -> dockerClient.inspectContainerCmd(name).exec());
    }

    private boolean isDockerAvailable() {
        try {
            dockerClient.pingCmd().exec();
            return true;
        } catch (Exception e) {
            LOG.warn("Docker daemon is not available for the runtime integration test", e);
            return false;
        }
    }
}
