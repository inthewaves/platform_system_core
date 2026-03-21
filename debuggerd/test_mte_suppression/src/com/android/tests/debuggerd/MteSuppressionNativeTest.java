package com.android.tests.debuggerd;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assume.assumeTrue;

import com.android.tradefed.log.LogUtil.CLog;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.util.CommandResult;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(DeviceJUnit4ClassRunner.class)
public class MteSuppressionNativeTest extends MteSuppressionTestBase {
  // Binary whose exe path matches the suppression pattern in suppression_pattern.h.
  private static final String MATCHED_BINARY = "mte_suppression_test_crash";
  // Same code, different name: exe path does NOT match any suppression entry.
  private static final String UNMATCHED_BINARY = "mte_suppression_test_crash_unmatched";

  // ===== Matched binary: suppression patterns apply =====

  @Test
  public void testMatchedPatternSurvives() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    CommandResult result = runNativeBinary(MATCHED_BINARY, "--suppressed",
        "testMatchedPatternSurvives");
    assertThat(result.getExitCode()).isEqualTo(0);
    assertThat(countTombstones("testMatchedPatternSurvives")).isEqualTo(1);
  }

  @Test
  public void testUnmatchedPatternCrashes() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    CommandResult result = runNativeBinary(MATCHED_BINARY, "--unsuppressed",
        "testUnmatchedPatternCrashes");
    assertThat(result.getExitCode()).isEqualTo(139);
    assertThat(countTombstones("testUnmatchedPatternCrashes")).isEqualTo(1);
  }

  @Test
  public void testCrossDsoPatternSurvives() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    CommandResult result = runNativeBinary(MATCHED_BINARY, "--cross-dso",
        "testCrossDsoPatternSurvives");
    assertThat(result.getExitCode()).isEqualTo(0);
    assertThat(countTombstones("testCrossDsoPatternSurvives")).isEqualTo(1);
  }

  @Test
  public void testSameDsoPatternCrashes() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    CommandResult result = runNativeBinary(MATCHED_BINARY, "--same-dso",
        "testSameDsoPatternCrashes");
    assertThat(result.getExitCode()).isEqualTo(139);
    assertThat(countTombstones("testSameDsoPatternCrashes")).isEqualTo(1);
  }

  @Test
  public void testNoGnuHashSurvives() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    CommandResult result = runNativeBinary(MATCHED_BINARY, "--nognuhash",
        "testNoGnuHashSurvives");
    assertThat(result.getExitCode()).isEqualTo(0);
    assertThat(countTombstones("testNoGnuHashSurvives")).isEqualTo(1);
  }

  @Test
  public void testLeafPatternSurvives() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    CommandResult result = runNativeBinary(MATCHED_BINARY, "--leaf",
        "testLeafPatternSurvives");
    assertThat(result.getExitCode()).isEqualTo(0);
    assertThat(countTombstones("testLeafPatternSurvives")).isEqualTo(1);
  }

  @Test
  public void testGapPatternSurvives() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    CommandResult result = runNativeBinary(MATCHED_BINARY, "--gap",
        "testGapPatternSurvives");
    assertThat(result.getExitCode()).isEqualTo(0);
    assertThat(countTombstones("testGapPatternSurvives")).isEqualTo(1);
  }

  @Test
  public void testUnsuppressedCrash() throws Exception {
    CommandResult result = runNativeBinary(MATCHED_BINARY, "--direct",
        "testUnsuppressedCrash");
    assertThat(result.getExitCode()).isEqualTo(139);
    assertThat(countTombstones("testUnsuppressedCrash")).isEqualTo(1);
  }

  // ===== Unmatched binary: no suppression entry for this exe path =====
  // Same code as the matched binary but installed under a different name.
  // The suppression pattern matches only /data/local/tmp/mte_suppression_test_crash,
  // so ALL modes should crash (exit 139) regardless of call stack.

  @Test
  public void testUnmatchedBinarySuppressedCrashes() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    CommandResult result = runNativeBinary(UNMATCHED_BINARY, "--suppressed",
        "testUnmatchedBinarySuppressedCrashes");
    assertThat(result.getExitCode()).isEqualTo(139);
  }

  @Test
  public void testUnmatchedBinaryUnsuppressedCrashes() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    CommandResult result = runNativeBinary(UNMATCHED_BINARY, "--unsuppressed",
        "testUnmatchedBinaryUnsuppressedCrashes");
    assertThat(result.getExitCode()).isEqualTo(139);
  }

  @Test
  public void testUnmatchedBinaryCrossDsoCrashes() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    CommandResult result = runNativeBinary(UNMATCHED_BINARY, "--cross-dso",
        "testUnmatchedBinaryCrossDsoCrashes");
    assertThat(result.getExitCode()).isEqualTo(139);
  }

  @Test
  public void testUnmatchedBinaryNoGnuHashCrashes() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    CommandResult result = runNativeBinary(UNMATCHED_BINARY, "--nognuhash",
        "testUnmatchedBinaryNoGnuHashCrashes");
    assertThat(result.getExitCode()).isEqualTo(139);
  }

  @Test
  public void testUnmatchedBinaryLeafCrashes() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    CommandResult result = runNativeBinary(UNMATCHED_BINARY, "--leaf",
        "testUnmatchedBinaryLeafCrashes");
    assertThat(result.getExitCode()).isEqualTo(139);
  }

  @Test
  public void testUnmatchedBinaryGapCrashes() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    CommandResult result = runNativeBinary(UNMATCHED_BINARY, "--gap",
        "testUnmatchedBinaryGapCrashes");
    assertThat(result.getExitCode()).isEqualTo(139);
  }

  @Test
  public void testUnmatchedBinaryDirectCrashes() throws Exception {
    CommandResult result = runNativeBinary(UNMATCHED_BINARY, "--direct",
        "testUnmatchedBinaryDirectCrashes");
    assertThat(result.getExitCode()).isEqualTo(139);
  }

  // ===== Benchmark =====

  @Test
  public void testSuppressionBenchmark() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));

    int iterations = 10;
    Pattern logPattern = Pattern.compile(
        "mte_suppress: check_mte_suppressions took (\\d+) us");
    List<Long> timings = new ArrayList<>();

    for (int i = 0; i < iterations; i++) {
      getDevice().executeShellCommand("logcat -c");
      NativeRunResult run = runNativeBinaryWithPid(MATCHED_BINARY, "--suppressed",
          "testSuppressionBenchmark");
      assertThat(run.result().getExitCode()).isEqualTo(0);
      String logcat = getDevice().executeShellCommand(
          "logcat -d --pid " + run.pid() + " -s libc:W --format=raw");
      Matcher m = logPattern.matcher(logcat);
      assertThat(m.find()).isTrue();
      timings.add(Long.parseLong(m.group(1)));
    }

    long min = Long.MAX_VALUE, max = 0, sum = 0;
    for (long us : timings) {
      if (us < min) min = us;
      if (us > max) max = us;
      sum += us;
    }
    long avg = sum / timings.size();

    CLog.i("MTE suppression benchmark: avg=%d us, min=%d us, max=%d us", avg, min, max);
    for (int i = 0; i < timings.size(); i++) {
      CLog.i("  iteration %d: %d us", i, timings.get(i));
    }
  }
}
