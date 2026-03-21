package com.android.tests.debuggerd;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assume.assumeTrue;

import com.android.server.os.TombstoneProtos.Tombstone;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import com.android.tradefed.util.CommandResult;
import java.util.ArrayList;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.List;
import java.util.UUID;
import org.junit.After;
import org.junit.Before;

/**
 * Base class for MTE suppression tests. Provides MTE availability checking,
 * tombstone management, and helpers for running native binaries and test apps.
 */
public abstract class MteSuppressionTestBase extends BaseHostJUnit4Test {
  protected static final String SUPPRESS_MATCH_LOG = "mte_suppress: MATCH pattern=";
  protected static final String SUPPRESS_NO_MATCH_LOG = "mte_suppress: no pattern matched";

  protected record NativeRunResult(int pid, CommandResult result) {}

  protected String mUUID;

  @Before
  public void setUp() throws Exception {
    mUUID = UUID.randomUUID().toString();

    // Verify that MTE is active on this device by triggering a direct (unsuppressed)
    // heap OOB. If the process isn't killed by SIGSEGV (exit 139), MTE is not
    // enabled, so skip all tests.
    CommandResult result = getDevice().executeShellV2Command(
        "LD_LIBRARY_PATH=/data/local/tmp "
        + "/data/local/tmp/mte_suppression_test_crash --direct setUp " + mUUID);
    assumeTrue("MTE must be enabled (expected SIGSEGV exit 139)",
               result.getExitCode() != null && result.getExitCode() == 139);
  }

  @After
  public void tearDown() throws Exception {
    String[] tombstones = getDevice().getChildren("/data/tombstones");
    if (tombstones == null) return;
    for (String tombstone : tombstones) {
      if (!tombstone.endsWith(".pb")) continue;
      String tombstonePath = "/data/tombstones/" + tombstone;
      Tombstone tombstoneProto = parseTombstone(tombstonePath);
      if (!tombstoneProto.getCommandLineList().stream().anyMatch(x -> x.contains(mUUID))) {
        continue;
      }
      getDevice().deleteFile(tombstonePath);
      getDevice().deleteFile(tombstonePath.substring(0, tombstonePath.length() - 3));
    }
  }

  protected Tombstone parseTombstone(String tombstonePath) throws Exception {
    File tombstoneFile = getDevice().pullFile(tombstonePath);
    InputStream istr = new FileInputStream(tombstoneFile);
    Tombstone tombstoneProto;
    try {
      tombstoneProto = Tombstone.parseFrom(istr);
    } finally {
      istr.close();
    }
    return tombstoneProto;
  }

  protected int countTombstones(String testName) throws Exception {
    return getTombstones(testName).size();
  }

  protected List<Tombstone> getTombstones(String testName) throws Exception {
    List<Tombstone> tombstonesForTest = new ArrayList<>();
    String[] tombstones = getDevice().getChildren("/data/tombstones");
    if (tombstones != null) {
      for (String tombstone : tombstones) {
        if (!tombstone.endsWith(".pb")) continue;
        String tombstonePath = "/data/tombstones/" + tombstone;
        Tombstone tombstoneProto = parseTombstone(tombstonePath);
        if (!tombstoneProto.getCommandLineList().stream().anyMatch(x -> x.contains(mUUID))) {
          continue;
        }
        if (!tombstoneProto.getCommandLineList().stream().anyMatch(x -> x.contains(testName))) {
          continue;
        }
        tombstonesForTest.add(tombstoneProto);
      }
    }
    return tombstonesForTest;
  }

  protected boolean isPermissiveMte() throws Exception {
    String global = getDevice().getProperty("persist.sys.mte.permissive");
    String deviceConfig = getDevice().getProperty(
        "persist.device_config.memory_safety_native.permissive.default");
    return "true".equals(global) || "1".equals(global)
        || "true".equals(deviceConfig) || "1".equals(deviceConfig);
  }

  /** Run a native test binary and return the result. */
  protected CommandResult runNativeBinary(String binaryName, String mode, String testName)
      throws Exception {
    return getDevice().executeShellV2Command(
        "LD_LIBRARY_PATH=/data/local/tmp "
        + "/data/local/tmp/" + binaryName + " " + mode + " " + testName + " " + mUUID);
  }

  /**
   * Run a native test binary and return both the shell command result and the pid the binary ran
   * under. `sh -c 'echo $$; exec ...'` prints the shell pid before `exec`, and `exec` then
   * replaces that shell with the test binary without changing the pid.
   */
  protected NativeRunResult runNativeBinaryWithPid(String binaryName, String mode, String testName)
      throws Exception {
    CommandResult result = getDevice().executeShellV2Command(
        "sh -c 'echo $$; export LD_LIBRARY_PATH=/data/local/tmp; exec "
        + "/data/local/tmp/" + binaryName + " " + mode + " " + testName + " " + mUUID + "'");

    String stdout = result.getStdout();
    assertThat(stdout).isNotNull();
    int newline = stdout.indexOf('\n');
    assertThat(newline).isAtLeast(0);
    int pid = Integer.parseInt(stdout.substring(0, newline).trim());
    return new NativeRunResult(pid, result);
  }

  /** Start an app activity with the given crash mode and return filtered logcat output. */
  protected String runAppAndGetLogcat(String packageName, String componentName, String mode)
      throws Exception {
    getDevice().executeShellCommand("am force-stop " + packageName);
    Thread.sleep(500);
    getDevice().executeShellCommand("logcat -c");
    getDevice().executeShellCommand(
        "am start -n " + componentName + " --es mode " + mode);
    Thread.sleep(3000);
    return getDevice().executeShellCommand(
        "logcat -d -s libc:* MteSuppressionTestApp:* --format=raw");
  }

  /**
   * Assert that an app survives the given crash mode (suppression pattern matched).
   * On permissive MTE, the process also survives but the match log may not appear.
   */
  protected void assertAppSurvives(String pkg, String component, String mode) throws Exception {
    String logcat = runAppAndGetLogcat(pkg, component, mode);
    if (!isPermissiveMte()) {
      assertThat(logcat).contains(SUPPRESS_MATCH_LOG);
    }
    assertThat(logcat).contains("Survived crash mode: " + mode);
  }

  /**
   * Assert that an app crashes because the binary/package matched a suppression
   * entry but the stack pattern did not match.
   */
  protected void assertAppCrashesPatternMismatch(String pkg, String component, String mode)
      throws Exception {
    assumeTrue("Permissive MTE suppresses all crashes", !isPermissiveMte());
    String logcat = runAppAndGetLogcat(pkg, component, mode);
    assertThat(logcat).contains(SUPPRESS_NO_MATCH_LOG);
    assertThat(logcat).doesNotContain("Survived crash mode: " + mode);
  }

  /**
   * Assert that an app crashes. Used for cases where no suppression entry matches
   * (unmatched binary/package) or direct faults with no pattern.
   */
  protected void assertAppCrashes(String pkg, String component, String mode) throws Exception {
    assumeTrue("Permissive MTE suppresses all crashes", !isPermissiveMte());
    String logcat = runAppAndGetLogcat(pkg, component, mode);
    assertThat(logcat).doesNotContain("Survived crash mode: " + mode);
  }
}
