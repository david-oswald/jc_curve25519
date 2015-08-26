/**
 * Copyright (c) 2015 Martin Paljak
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package pro.javacard.ant;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Vector;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.Task;
import org.apache.tools.ant.taskdefs.Java;
import org.apache.tools.ant.taskdefs.Javac;
import org.apache.tools.ant.types.Environment.Variable;
import org.apache.tools.ant.types.Path;

public class JavaCard extends Task {
	private static enum JC {
		V2, V3
	}

	private String master_jckit_path = null;
	private Vector<JCCap> packages = new Vector<>();

	private static String hexAID(byte[] aid) {
		StringBuffer hexaid = new StringBuffer();
		for (byte b : aid) {
			hexaid.append(String.format("0x%02X", b));
			hexaid.append(":");
		}
		String hex = hexaid.toString();
		// Cut off the final colon
		return hex.substring(0, hex.length() - 1);
	}

	public void setJCKit(String msg) {
		master_jckit_path = msg;
	}

	public JC detectSDK(String jckit_path) {
		// Identify jckit type
		if (!new File(jckit_path).exists()) {
			throw new BuildException("JavaCard SDK folder " + jckit_path + " does not exist!");
		}
		if (Paths.get(jckit_path, "lib", "tools.jar").toFile().exists()) {
			log("JavaCard 3.x SDK detected in " + jckit_path, Project.MSG_INFO);
			return JC.V3;
		} else if (Paths.get(jckit_path, "lib", "converter.jar").toFile().exists()) {
			log("JavaCard 2.x SDK detected in " + jckit_path, Project.MSG_INFO);
			return JC.V2;
		} else {
			throw new BuildException("Could not detect a JavaCard SDK in " + Paths.get(jckit_path).toAbsolutePath());
		}
	}

	public JCCap createCap() {
		JCCap pkg = new JCCap();
		packages.add(pkg);
		return pkg;
	}

	public void execute() {
		for (JCCap p : packages) {
			p.execute();
		}
	}

	public class JCApplet {
		private String klass = null;
		private byte[] aid = null;

		public JCApplet() {
		}

		public void setCLass(String msg) {
			klass = msg;
		}

		public void setAID(String msg) {
			try {
				aid = stringToBin(msg);
				if (aid.length < 5 || aid.length > 16) {
					throw new BuildException("Applet AID must be between 5 and 16 bytes: " + aid.length);
				}
			} catch (IllegalArgumentException e) {
				throw new BuildException("Not a correct applet AID: " + e.getMessage());
			}
		}
	}

	@SuppressWarnings("serial")
	public class HelpingBuildException extends BuildException {
		public HelpingBuildException(String msg) {
			super(msg + "\n\nPLEASE READ https://github.com/martinpaljak/ant-javacard#syntax");
		}
	}
	public class JCCap extends Task {
		private JC build_type = JC.V2;
		private String classes_path = null;
		private String sources_path = null;
		private String package_name = null;
		private byte[] package_aid = null;
		private String package_version = null;
		private Vector<JCApplet> raw_applets = new Vector<>();
		private Vector<JCImport> raw_imports = new Vector<>();
		private String output_file = null;
		private String jckit_path = null;

		public JCCap() {
		}

		public void setOutput(String msg) {
			output_file = msg;
		}

		public void setPackage(String msg) {
			package_name = msg;
		}

		public void setClasses(String msg) {
			classes_path = msg;
		}

		public void setVersion(String msg) {
			package_version = msg;
		}

		public void setSources(String arg) {
			sources_path = arg;
		}

		public void setAID(String msg) {
			try {
				package_aid = stringToBin(msg);
				if (package_aid.length < 5 || package_aid.length > 16)
					throw new BuildException("Package AID must be between 5 and 16 bytes: " + package_aid.length);

			} catch (IllegalArgumentException e) {
				throw new BuildException("Not a correct package AID: " + e.getMessage());
			}
		}

		/** Many applets inside one package */
		public JCApplet createApplet() {
			JCApplet applet = new JCApplet();
			raw_applets.add(applet);
			return applet;
		}

		/** Many imports inside one package */
		public JCImport createImport() {
			JCImport imp = new JCImport();
			raw_imports.add(imp);
			return imp;
		}

		// Check that arguments are sufficient and do some DWIM
		private void check() {
			String jckit_env = System.getenv("JC_HOME");
			if (jckit_path == null && master_jckit_path == null && jckit_env == null) {
				throw new HelpingBuildException("Must specify JavaCard SDK path or set JC_HOME");
			}

			if (jckit_path == null) {
				// if master file is specified but does not exist, override
				// with environment, variable, if specified.
				if (master_jckit_path != null && !new File(master_jckit_path).exists() && jckit_env != null) {
					log("INFO: using JC_HOME because " + master_jckit_path + " does not exist", Project.MSG_INFO);
					jckit_path = jckit_env;
				} else if (master_jckit_path == null && jckit_env != null) {
					jckit_path = jckit_env;
				} else {
					jckit_path = master_jckit_path;
				}
			}

			if (jckit_path == null) {
				throw new HelpingBuildException("No usable JavaCard SDK referenced");
			}
			build_type = detectSDK(jckit_path);

			// sources or classes must be set
			if (sources_path == null && classes_path == null) {
				throw new HelpingBuildException("Must specify sources or classes");
			}
			// Check package version
			if (package_version == null) {
				package_version = "0.0";
			} else {
				if (!package_version.matches("^[0-9].[0-9]$")) {
					throw new HelpingBuildException("Incorrect package version: " + package_version);
				}
			}

			// Construct applets and fill in missing bits from package info, if
			int applet_counter = 0;
			// necessary
			for (JCApplet a : raw_applets) {
				// Keep count for automagic numbering
				applet_counter = applet_counter + 1;

				if (a.klass == null) {
					throw new HelpingBuildException("Applet class is missing");
				}
				// If package name is present, must match the applet
				if (package_name != null) {
					if (!a.klass.contains(".")) {
						a.klass = package_name + "." + a.klass;
					} else if (!a.klass.startsWith(package_name)) {
						throw new HelpingBuildException("Applet class " + a.klass + " is not in package " + package_name);
					}
				} else {
					String pkgname = a.klass.substring(0, a.klass.lastIndexOf("."));
					log("Setting package name to " + pkgname, Project.MSG_INFO);
					package_name = pkgname;
				}

				// If applet AID is present, must match the package AID
				if (package_aid != null) {
					if (a.aid != null) {
						// RID-s must match
						if (!Arrays.equals(Arrays.copyOf(package_aid, 5), Arrays.copyOf(a.aid, 5))) {
							throw new HelpingBuildException("Package RID does not match Applet RID");
						}
					} else {
						// make "magic" applet AID from package_aid + counter
						a.aid = Arrays.copyOf(package_aid, package_aid.length + 1);
						a.aid[package_aid.length] = (byte) applet_counter;
						log("INFO: generated applet AID: " + hexAID(a.aid) + " for " + a.klass, Project.MSG_INFO);
					}
				} else {
					// if package AID is empty, just set it to the minimal from
					// applet
					if (a.aid != null) {
						package_aid = Arrays.copyOf(a.aid, 5);
					} else {
						throw new HelpingBuildException("Both package AID and applet AID are missing!");
					}
				}
			}

			// Check package AID
			if (package_aid == null) {
				throw new HelpingBuildException("Must specify package AID");
			}

			// Check output file
			if (output_file == null) {
				throw new HelpingBuildException("Must specify output file");
			}
			// Nice info
			log("Building CAP with " + applet_counter + " applet(s) from package " + package_name, Project.MSG_INFO);
			for (JCApplet app : raw_applets) {
				log(app.klass + " " + encodeHexString(app.aid), Project.MSG_INFO);
			}
		}

		private File makeTmpFolder(String key) {
			try {
				File t = Files.createTempDirectory("antjc").toFile();
				t.deleteOnExit();
				return t;
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		private void compile() {
			Javac j = new Javac();
			j.setProject(getProject());
			j.setTaskName("compile");

			j.setSrcdir(new Path(getProject(), sources_path));

			File tmp;
			if (classes_path != null) {
				tmp = new File(classes_path);
				if (!tmp.exists()) {
					tmp.mkdir();
				}
			} else {
				// Generate temporary folder
				tmp = makeTmpFolder("classes");
				classes_path = tmp.getAbsolutePath();
			}

			j.setDestdir(tmp);

			// TODO: detect
			// 2.2.1 max 1.2
			// 2.2.2 max 1.3
			// 3.0.3 max 1.6. Overrides come in 1.5
			if (build_type == JC.V2) {
				j.setTarget("1.2");
				j.setSource("1.2");
			} else if (build_type == JC.V3) {
				j.setTarget("1.5");
				j.setSource("1.5");
			}
			j.setIncludeantruntime(false);
			// TODO: crate attribute for debug
			j.createCompilerArg().setValue("-Xlint");
			j.createCompilerArg().setValue("-Xlint:-options");
			j.createCompilerArg().setValue("-Xlint:-serial");
			j.setFailonerror(true);
			j.setFork(true);
			// set classpath
			Path cp = j.createClasspath();
			String api = null;
			if (build_type == JC.V3) {
				api = Paths.get(jckit_path, "lib", "api_classic.jar").toAbsolutePath().toString();
			} else if (build_type == JC.V2) {
				api = Paths.get(jckit_path, "lib", "api.jar").toAbsolutePath().toString();
			}
			cp.append(new Path(getProject(), api));
			for (JCImport i : raw_imports) {
				cp.append(new Path(getProject(), i.jar));
			}
			j.execute();
		}

		public void execute() {
			// Convert
			check();

			// Compile first if necessary
			if (sources_path != null) {
				compile();
			}
			// construct the Java task that executes converter
			Java j = new Java(this);
			// classpath to jckit bits
			Path cp = j.createClasspath();
			// converter
			File jar = null;
			if (build_type == JC.V2) {
				// XXX: this should be with less lines ?
				jar = Paths.get(jckit_path, "lib", "converter.jar").toFile();
				Path jarpath = new Path(getProject());
				jarpath.setLocation(jar);
				cp.append(jarpath);
				jar = Paths.get(jckit_path, "lib", "offcardverifier.jar").toFile();
				jarpath = new Path(getProject());
				jarpath.setLocation(jar);
				cp.append(jarpath);
			} else if (build_type == JC.V3) {
				jar = Paths.get(jckit_path, "lib", "tools.jar").toFile();
				Path jarpath = new Path(getProject());
				jarpath.setLocation(jar);
				cp.append(jarpath);
			}

			File applet_folder = makeTmpFolder("applet");
			j.createArg().setLine("-classdir '" + classes_path + "'");
			j.createArg().setLine("-d '" + applet_folder.getAbsolutePath() + "'");

			// Construct exportpath
			String exps = Paths.get(jckit_path, "api_export_files").toString();
			for (JCImport imp : raw_imports) {
				exps = exps + File.pathSeparatorChar + Paths.get(imp.exps).toAbsolutePath().toString();
			}
			j.createArg().setLine("-exportpath '" + exps + "'");
			// j.createArg().setLine("-nowarn");
			j.createArg().setLine("-verbose");
			j.createArg().setLine("-nobanner");

			j.createArg().setLine("-out CAP EXP JCA");
			for (JCApplet app : raw_applets) {
				j.createArg().setLine("-applet " + hexAID(app.aid) + " " + app.klass);
			}
			j.createArg().setLine(package_name + " " + hexAID(package_aid) + " " + package_version);

			// Call converter
			if (build_type == JC.V2) {
				j.setClassname("com.sun.javacard.converter.Converter");
			} else if (build_type == JC.V3) {
				j.setClassname("com.sun.javacard.converter.Main");
				// XXX: See https://community.oracle.com/message/10452555
				Variable jchome = new Variable();
				jchome.setKey("jc.home");
				jchome.setValue(jckit_path);
				j.addSysproperty(jchome);
			}
			j.setFailonerror(true);
			j.setFork(true);

			log("cmdline: " + j.getCommandLine(), Project.MSG_VERBOSE);
			j.execute();

			// Copy result to output
			if (output_file != null) {
				String ln = package_name;
				if (ln.lastIndexOf(".") != -1) {
					ln = ln.substring(ln.lastIndexOf(".") + 1);
				}
				File cap = Paths.get(applet_folder.getAbsolutePath(), package_name.replace(".", File.separator), "javacard", ln + ".cap").toFile();
				if (!cap.exists()) {
					throw new BuildException("Can not find CAP in " + cap.toString());
				}

				try {
					File opf = new File(output_file);
					if (!opf.exists())
						opf.createNewFile();
					Files.copy(cap.toPath(), new FileOutputStream(opf));
					log("CAP saved to " + opf.getAbsolutePath(), Project.MSG_INFO);
				} catch (IOException e) {
					throw new BuildException("Can not copy output CAP", e);
				}
			}
		}

		public void setJCKit(String msg) {
			jckit_path = msg;
		}
	}

	public class JCImport {
		String exps = null;
		String jar = null;

		public void setExps(String msg) {
			exps = msg;
		}

		public void setJar(String msg) {
			jar = msg;
		}
	}

	// This code has been taken from Apache commons-codec 1.7 (License: Apache
	// 2.0)
	private static final char[] LOWER_HEX = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

	public static String encodeHexString(final byte[] data) {

		final int l = data.length;
		final char[] out = new char[l << 1];
		// two characters form the hex value.
		for (int i = 0, j = 0; i < l; i++) {
			out[j++] = LOWER_HEX[(0xF0 & data[i]) >>> 4];
			out[j++] = LOWER_HEX[0x0F & data[i]];
		}
		return new String(out);
	}

	public static byte[] decodeHexString(String str) {
		char data[] = str.toCharArray();
		final int len = data.length;
		if ((len & 0x01) != 0) {
			throw new IllegalArgumentException("Odd number of characters: " + str);
		}
		final byte[] out = new byte[len >> 1];
		// two characters form the hex value.
		for (int i = 0, j = 0; j < len; i++) {
			int f = Character.digit(data[j], 16) << 4;
			j++;
			f = f | Character.digit(data[j], 16);
			j++;
			out[i] = (byte) (f & 0xFF);
		}
		return out;
	}

	// End of copied code from commons-codec

	public static byte[] stringToBin(String s) {
		s = s.toLowerCase().replaceAll(" ", "").replaceAll(":", "");
		s = s.replaceAll("0x", "").replaceAll("\n", "").replaceAll("\t", "");
		s = s.replaceAll(";", "");
		return decodeHexString(s);
	}

}
