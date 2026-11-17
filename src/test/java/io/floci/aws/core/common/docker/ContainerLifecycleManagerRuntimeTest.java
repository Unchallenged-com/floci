package io.floci.aws.core.common.docker;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.CreateContainerCmd;
import com.github.dockerjava.api.command.CreateContainerResponse;
import com.github.dockerjava.api.command.CreateVolumeCmd;
import com.github.dockerjava.api.command.InspectVolumeCmd;
import com.github.dockerjava.api.command.RemoveContainerCmd;
import com.github.dockerjava.api.command.StartContainerCmd;
import com.github.dockerjava.api.command.WaitContainerCmd;
import com.github.dockerjava.api.exception.NotFoundException;
import com.github.dockerjava.api.model.HostConfig;
import com.github.dockerjava.core.command.WaitContainerResultCallback;
import io.floci.aws.config.EmulatorConfig;
import io.floci.aws.services.lambda.launcher.ImageCacheService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.OptionalInt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A container's Docker runtime reaches HostConfig.Runtime, as {@code docker run --runtime} sets it; a container that
 * names none, with no {@code floci.docker.runtime}, is left on the daemon's default runtime. The storage init helpers,
 * which are not built from a spec, run with {@code floci.docker.runtime} too.
 */
@ExtendWith(MockitoExtension.class)
class ContainerLifecycleManagerRuntimeTest {

    @Mock
    DockerClient dockerClient;

    @Mock
    ImageCacheService imageCacheService;

    @Mock
    ContainerDetector containerDetector;

    @Mock
    EmulatorConfig config;

    @Mock
    EmulatorConfig.DockerConfig dockerConfig;

    @Mock
    EmulatorConfig.TlsConfig tlsConfig;

    @BeforeEach
    void setUp() {
        lenient().when(config.docker()).thenReturn(dockerConfig);
        lenient().when(config.tls()).thenReturn(tlsConfig);
        lenient().when(dockerConfig.resourceNamespace()).thenReturn(Optional.empty());
        lenient().when(imageCacheService.ensureImageExists(any()))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void aSpecsRuntimeReachesTheHostConfig() {
        CreateContainerCmd createCmd = stubCreateContainer();

        manager().create(new ContainerBuilder(null, null, null).newContainer("busybox:stable")
                .withRuntime("kata")
                .build());

        assertEquals("kata", capturedHostConfig(createCmd).getRuntime());
    }

    @Test
    void aSpecWithoutRuntimeLeavesTheContainerOnTheDaemonsDefault() {
        CreateContainerCmd createCmd = stubCreateContainer();

        manager().create(new ContainerSpec("busybox:stable"));

        assertNull(capturedHostConfig(createCmd).getRuntime());
    }

    @Test
    void sharedVolumeInitHelperRunsWithTheGlobalRuntime() {
        when(dockerConfig.runtime()).thenReturn(Optional.of("runsc"));
        stubVolumeCreation("shared");
        CreateContainerCmd createCmd = stubCreateContainer();
        stubHelperRun();

        manager().ensureSharedVolume("shared", OptionalInt.of(1001), OptionalInt.of(1001),
                Optional.of("2775"), "busybox:stable");

        assertEquals("runsc", capturedHostConfig(createCmd).getRuntime());
    }

    @Test
    void bindDirectoryHelperRunsWithTheGlobalRuntime() {
        when(dockerConfig.runtime()).thenReturn(Optional.of("runsc"));
        CreateContainerCmd createCmd = stubCreateContainer();
        stubHelperRun();

        manager().ensureBindDirectory("/srv/data", "busybox:stable", "/data");

        assertEquals("runsc", capturedHostConfig(createCmd).getRuntime());
    }

    @Test
    void bindDirectoryHelperStaysOnTheDaemonsDefaultWithoutAGlobalRuntime() {
        CreateContainerCmd createCmd = stubCreateContainer();
        stubHelperRun();

        manager().ensureBindDirectory("/srv/data", "busybox:stable", "/data");

        assertNull(capturedHostConfig(createCmd).getRuntime());
    }

    private ContainerLifecycleManager manager() {
        return new ContainerLifecycleManager(dockerClient, imageCacheService, containerDetector, config);
    }

    private void stubVolumeCreation(String volumeName) {
        InspectVolumeCmd inspectVolumeCmd = mock(InspectVolumeCmd.class);
        when(dockerClient.inspectVolumeCmd(volumeName)).thenReturn(inspectVolumeCmd);
        when(inspectVolumeCmd.exec()).thenThrow(new NotFoundException("missing"));
        when(dockerClient.createVolumeCmd()).thenReturn(mock(CreateVolumeCmd.class, RETURNS_SELF));
    }

    private void stubHelperRun() {
        when(dockerClient.startContainerCmd("container-id")).thenReturn(mock(StartContainerCmd.class));
        WaitContainerCmd waitCmd = mock(WaitContainerCmd.class);
        when(dockerClient.waitContainerCmd("container-id")).thenReturn(waitCmd);
        WaitContainerResultCallback waitCallback = mock(WaitContainerResultCallback.class);
        when(waitCmd.exec(any(WaitContainerResultCallback.class))).thenReturn(waitCallback);
        when(waitCallback.awaitStatusCode(anyLong(), any())).thenReturn(0);
        when(dockerClient.removeContainerCmd("container-id"))
                .thenReturn(mock(RemoveContainerCmd.class, RETURNS_SELF));
    }

    private CreateContainerCmd stubCreateContainer() {
        CreateContainerCmd createCmd = mock(CreateContainerCmd.class, RETURNS_SELF);
        when(dockerClient.createContainerCmd("busybox:stable")).thenReturn(createCmd);
        CreateContainerResponse response = mock(CreateContainerResponse.class);
        when(response.getId()).thenReturn("container-id");
        when(createCmd.exec()).thenReturn(response);
        return createCmd;
    }

    private static HostConfig capturedHostConfig(CreateContainerCmd createCmd) {
        ArgumentCaptor<HostConfig> hostConfig = ArgumentCaptor.forClass(HostConfig.class);
        verify(createCmd).withHostConfig(hostConfig.capture());
        return hostConfig.getValue();
    }
}
