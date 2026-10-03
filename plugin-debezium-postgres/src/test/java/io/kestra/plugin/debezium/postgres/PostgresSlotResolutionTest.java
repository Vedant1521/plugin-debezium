package io.kestra.plugin.debezium.postgres;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContext;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.utils.TestsUtils;

import jakarta.inject.Inject;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

@KestraTest
class PostgresSlotResolutionTest {

    private static final Pattern PG_SLOT_PATTERN = Pattern.compile("^[a-z0-9_]{1,63}$");

    @Inject
    private RunContextFactory runContextFactory;

    private Capture.CaptureBuilder<?, ?> createCaptureBuilder(String id) {
        return Capture.builder()
            .id(id)
            .type(Capture.class.getName())
            .hostname(Property.ofValue("localhost"))
            .port(Property.ofValue("5432"))
            .database(Property.ofValue("postgres"));
    }

    @Test
    void defaultSlotNameIsDerivedAndCompliesWithPostgresRules() throws Exception {
        Capture task = createCaptureBuilder("task_cdc").build();

        RunContext runContext = TestsUtils.mockRunContext(runContextFactory, task, Map.of());

        String slotName = PostgresService.resolveSlotName(runContext, task);

        assertThat(slotName, startsWith("kestra_"));
        assertThat(slotName.length(), is(15)); // "kestra_" (7) + 8 hex chars = 15
        assertTrue(PG_SLOT_PATTERN.matcher(slotName).matches(), "Slot name must match PostgreSQL slot naming rules");
    }

    @Test
    void defaultPublicationNameIsDerivedAndCompliesWithPostgresRules() throws Exception {
        Capture task = createCaptureBuilder("task_cdc").build();

        RunContext runContext = TestsUtils.mockRunContext(runContextFactory, task, Map.of());

        String publicationName = PostgresService.resolvePublicationName(runContext, task);

        assertThat(publicationName, startsWith("kestra_pub_"));
        assertThat(publicationName.length(), is(19)); // "kestra_pub_" (11) + 8 hex chars = 19
        assertTrue(PG_SLOT_PATTERN.matcher(publicationName).matches(), "Publication name must match PostgreSQL identifier rules");
    }

    @Test
    void distinctTasksInSameFlowDeriveDistinctSlotsAndPublications() throws Exception {
        Capture taskA = createCaptureBuilder("task_a").build();
        Capture taskB = createCaptureBuilder("task_b").build();

        RunContext runContextA = TestsUtils.mockRunContext(runContextFactory, taskA, Map.of());
        RunContext runContextB = TestsUtils.mockRunContext(runContextFactory, taskB, Map.of());

        String slotA = PostgresService.resolveSlotName(runContextA, taskA);
        String slotB = PostgresService.resolveSlotName(runContextB, taskB);

        String pubA = PostgresService.resolvePublicationName(runContextA, taskA);
        String pubB = PostgresService.resolvePublicationName(runContextB, taskB);

        assertThat(
            "Tasks in the same flow must have distinct slots to prevent Scenario A duplicate replays",
            slotA, not(equalTo(slotB))
        );
        assertThat(
            "Tasks in the same flow must have distinct publications",
            pubA, not(equalTo(pubB))
        );
    }

    @Test
    void derivedNamesAreStableAcrossExecutions() throws Exception {
        Capture task1 = createCaptureBuilder("task_stable").build();
        Capture task2 = createCaptureBuilder("task_stable").build();

        RunContext runContext1 = TestsUtils.mockRunContext(runContextFactory, task1, Map.of());
        RunContext runContext2 = TestsUtils.mockRunContext(runContextFactory, task2, Map.of());

        String slot1 = PostgresService.resolveSlotName(runContext1, task1);
        String slot2 = PostgresService.resolveSlotName(runContext2, task2);

        assertThat(
            "Same task identity must resolve to the identical slot name across runs",
            slot1, equalTo(slot2)
        );
    }

    @Test
    void explicitSlotNameAndPublicationNameAreRespected() throws Exception {
        Capture task = createCaptureBuilder("task_custom")
            .slotName(Property.ofValue("my_custom_slot"))
            .publicationName(Property.ofValue("my_custom_pub"))
            .build();

        RunContext runContext = TestsUtils.mockRunContext(runContextFactory, task, Map.of());

        assertThat(PostgresService.resolveSlotName(runContext, task), is("my_custom_slot"));
        assertThat(PostgresService.resolvePublicationName(runContext, task), is("my_custom_pub"));
    }

    @Test
    void explicitExpressionSlotNameAndPublicationNameAreRendered() throws Exception {
        Capture task = createCaptureBuilder("task_custom_expr")
            .slotName(Property.ofExpression("{{ inputs.slot }}"))
            .publicationName(Property.ofExpression("{{ inputs.pub }}"))
            .build();

        RunContext runContext = TestsUtils.mockRunContext(
            runContextFactory, task, Map.of(
                "slot", "rendered_slot",
                "pub", "rendered_pub"
            )
        );

        assertThat(PostgresService.resolveSlotName(runContext, task), is("rendered_slot"));
        assertThat(PostgresService.resolvePublicationName(runContext, task), is("rendered_pub"));
    }

    @Test
    void legacyRestoredOffsetPreservesLegacyDefaults(@TempDir Path tmp) throws Exception {
        Path offsetFile = tmp.resolve("offsets.dat");
        Files.writeString(offsetFile, "legacy_offset_payload");

        Capture task = createCaptureBuilder("task_legacy").build();

        RunContext runContext = TestsUtils.mockRunContext(runContextFactory, task, Map.of());

        String slotName = PostgresService.resolveSlotName(runContext, task, offsetFile, null);
        String pubName = PostgresService.resolvePublicationName(runContext, task, offsetFile, null);

        assertThat(
            "Existing tasks with restored offset state must keep resuming from legacy slot",
            slotName, is(PostgresService.LEGACY_SLOT_NAME)
        );
        assertThat(
            "Existing tasks with restored offset state must keep using legacy publication",
            pubName, is(PostgresService.LEGACY_PUBLICATION_NAME)
        );
    }

    @Test
    void explicitSlotNameOverridesLegacyRestoredOffset(@TempDir Path tmp) throws Exception {
        Path offsetFile = tmp.resolve("offsets.dat");
        Files.writeString(offsetFile, "legacy_offset_payload");

        Capture task = createCaptureBuilder("task_legacy_override")
            .slotName(Property.ofValue("explicit_slot"))
            .publicationName(Property.ofValue("explicit_pub"))
            .build();

        RunContext runContext = TestsUtils.mockRunContext(runContextFactory, task, Map.of());

        String slotName = PostgresService.resolveSlotName(runContext, task, offsetFile, null);
        String pubName = PostgresService.resolvePublicationName(runContext, task, offsetFile, null);

        assertThat(slotName, is("explicit_slot"));
        assertThat(pubName, is("explicit_pub"));
    }

    @Test
    void triggerDelegatesToCaptureWithDerivedSlotName() throws Exception {
        Trigger trigger = Trigger.builder()
            .id("trigger_cdc")
            .type(Trigger.class.getName())
            .build();

        Capture task = createCaptureBuilder(trigger.getId())
            .slotName(trigger.getSlotName())
            .publicationName(trigger.getPublicationName())
            .build();

        RunContext runContext = TestsUtils.mockRunContext(runContextFactory, task, Map.of());

        String slotName = PostgresService.resolveSlotName(runContext, task);
        assertThat(slotName, startsWith("kestra_"));
        assertTrue(PG_SLOT_PATTERN.matcher(slotName).matches());
    }

    @Test
    void realtimeTriggerDelegatesToCaptureWithDerivedSlotName() throws Exception {
        RealtimeTrigger trigger = RealtimeTrigger.builder()
            .id("realtime_cdc")
            .type(RealtimeTrigger.class.getName())
            .build();

        Capture task = createCaptureBuilder(trigger.getId())
            .slotName(trigger.getSlotName())
            .publicationName(trigger.getPublicationName())
            .build();

        RunContext runContext = TestsUtils.mockRunContext(runContextFactory, task, Map.of());

        String slotName = PostgresService.resolveSlotName(runContext, task);
        assertThat(slotName, startsWith("kestra_"));
        assertTrue(PG_SLOT_PATTERN.matcher(slotName).matches());
    }
}
