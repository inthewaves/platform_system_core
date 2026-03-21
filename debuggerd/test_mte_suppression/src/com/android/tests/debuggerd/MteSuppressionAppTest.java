package com.android.tests.debuggerd;

import static org.junit.Assume.assumeTrue;

import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(DeviceJUnit4ClassRunner.class)
public class MteSuppressionAppTest extends MteSuppressionTestBase {
  private static final String ACTIVITY_CLASS =
      "com.android.tests.debuggerd.mtesuppression.CrashActivity";

  // Matching package, embedded native libs (DSOs resolved via DT_SONAME from APK).
  private static final String EMBEDDED_PKG = "com.android.tests.debuggerd.mtesuppression";
  private static final String EMBEDDED_COMPONENT = EMBEDDED_PKG + "/" + ACTIVITY_CLASS;

  // Matching package, extracted native libs (DSOs resolved via basename on disk).
  private static final String EXTRACTED_PKG =
      "com.android.tests.debuggerd.mtesuppression.extracted";
  private static final String EXTRACTED_COMPONENT = EXTRACTED_PKG + "/" + ACTIVITY_CLASS;

  // Non-matching package: no BinarySuppression entry, all modes should crash.
  private static final String UNMATCHED_PKG =
      "com.android.tests.debuggerd.mtesuppression.unmatched";
  private static final String UNMATCHED_COMPONENT = UNMATCHED_PKG + "/" + ACTIVITY_CLASS;

  // ===== Embedded app (matching package, native libs loaded from APK) =====

  @Test
  public void testAppEmbeddedMatchedPatternSurvives() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    assertAppSurvives(EMBEDDED_PKG, EMBEDDED_COMPONENT, "suppressed");
  }

  @Test
  public void testAppEmbeddedUnmatchedPatternCrashes() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    assertAppCrashesPatternMismatch(EMBEDDED_PKG, EMBEDDED_COMPONENT, "unsuppressed");
  }

  @Test
  public void testAppEmbeddedDirectCrash() throws Exception {
    assertAppCrashes(EMBEDDED_PKG, EMBEDDED_COMPONENT, "direct");
  }

  @Test
  public void testAppEmbeddedCrossDsoPatternSurvives() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    assertAppSurvives(EMBEDDED_PKG, EMBEDDED_COMPONENT, "cross-dso");
  }

  @Test
  public void testAppEmbeddedSameDsoPatternCrashes() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    assertAppCrashesPatternMismatch(EMBEDDED_PKG, EMBEDDED_COMPONENT, "same-dso");
  }

  @Test
  public void testAppEmbeddedNoGnuHashSurvives() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    assertAppSurvives(EMBEDDED_PKG, EMBEDDED_COMPONENT, "nognuhash");
  }

  @Test
  public void testAppEmbeddedLeafPatternSurvives() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    assertAppSurvives(EMBEDDED_PKG, EMBEDDED_COMPONENT, "leaf");
  }

  @Test
  public void testAppEmbeddedGapPatternSurvives() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    assertAppSurvives(EMBEDDED_PKG, EMBEDDED_COMPONENT, "gap");
  }

  // ===== Extracted app (matching package, native libs extracted to disk) =====

  @Test
  public void testAppExtractedMatchedPatternSurvives() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    assertAppSurvives(EXTRACTED_PKG, EXTRACTED_COMPONENT, "suppressed");
  }

  @Test
  public void testAppExtractedUnmatchedPatternCrashes() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    assertAppCrashesPatternMismatch(EXTRACTED_PKG, EXTRACTED_COMPONENT, "unsuppressed");
  }

  @Test
  public void testAppExtractedDirectCrash() throws Exception {
    assertAppCrashes(EXTRACTED_PKG, EXTRACTED_COMPONENT, "direct");
  }

  @Test
  public void testAppExtractedCrossDsoPatternSurvives() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    assertAppSurvives(EXTRACTED_PKG, EXTRACTED_COMPONENT, "cross-dso");
  }

  @Test
  public void testAppExtractedSameDsoPatternCrashes() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    assertAppCrashesPatternMismatch(EXTRACTED_PKG, EXTRACTED_COMPONENT, "same-dso");
  }

  @Test
  public void testAppExtractedNoGnuHashSurvives() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    assertAppSurvives(EXTRACTED_PKG, EXTRACTED_COMPONENT, "nognuhash");
  }

  @Test
  public void testAppExtractedLeafPatternSurvives() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    assertAppSurvives(EXTRACTED_PKG, EXTRACTED_COMPONENT, "leaf");
  }

  @Test
  public void testAppExtractedGapPatternSurvives() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    assertAppSurvives(EXTRACTED_PKG, EXTRACTED_COMPONENT, "gap");
  }

  // ===== Unmatched app (non-matching package, no suppression entry) =====
  // The suppression table has no entry for this package. find_binary_suppression
  // returns null, so ALL modes crash regardless of call stack.

  @Test
  public void testAppUnmatchedSuppressedCrashes() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    assertAppCrashes(UNMATCHED_PKG, UNMATCHED_COMPONENT, "suppressed");
  }

  @Test
  public void testAppUnmatchedUnsuppressedCrashes() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    assertAppCrashes(UNMATCHED_PKG, UNMATCHED_COMPONENT, "unsuppressed");
  }

  @Test
  public void testAppUnmatchedDirectCrashes() throws Exception {
    assertAppCrashes(UNMATCHED_PKG, UNMATCHED_COMPONENT, "direct");
  }

  @Test
  public void testAppUnmatchedCrossDsoCrashes() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    assertAppCrashes(UNMATCHED_PKG, UNMATCHED_COMPONENT, "cross-dso");
  }

  @Test
  public void testAppUnmatchedNoGnuHashCrashes() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    assertAppCrashes(UNMATCHED_PKG, UNMATCHED_COMPONENT, "nognuhash");
  }

  @Test
  public void testAppUnmatchedLeafCrashes() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    assertAppCrashes(UNMATCHED_PKG, UNMATCHED_COMPONENT, "leaf");
  }

  @Test
  public void testAppUnmatchedGapCrashes() throws Exception {
    assumeTrue("Test requires userdebug or eng build",
               !"user".equals(getDevice().getProperty("ro.build.type")));
    assertAppCrashes(UNMATCHED_PKG, UNMATCHED_COMPONENT, "gap");
  }
}
