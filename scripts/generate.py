#!/usr/bin/env python3
"""Deterministic 1000-module fixture. Never removes existing source files."""
import hashlib, json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def module_path(root,index):
    return root/'modules'/f'lib{index:04d}'

def generate(root=ROOT):
    def write(name, text):
        from locking import project_path
        p = project_path(root,root / name)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    write('settings.gradle', '''pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement { repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS); repositories { google(); mavenCentral() } }
rootProject.name = 'GradleBench'
(0..<1000).each {
    def name = String.format('lib%04d', it)
    include(":${name}")
    project(":${name}").projectDir = file("modules/${name}")
}
''')
    write('gradle.properties', '''org.gradle.configuration-cache=false
org.gradle.configureondemand=false
org.gradle.caching=false
org.gradle.parallel=false
org.gradle.workers.max=4
org.gradle.jvmargs=-Xms512m -Xmx6g -XX:+UseG1GC -Dfile.encoding=UTF-8
android.useAndroidX=false
android.enableJetifier=false
''')
    write('build.gradle', '''import groovy.json.JsonOutput
import org.gradle.api.artifacts.result.UnresolvedDependencyResult
plugins { id 'com.android.library' version '7.4.2' apply false }
def configured = new LinkedHashSet<String>()
subprojects {
    apply plugin: 'com.android.library'
    android {
        namespace "org.gradlescope.${project.name}"
        compileSdk 33
        buildToolsVersion '30.0.3'
        defaultConfig { minSdk 21; targetSdk 33 }
        compileOptions { sourceCompatibility JavaVersion.VERSION_11; targetCompatibility JavaVersion.VERSION_11 }
    }
    afterEvaluate { configured.add(path) }
}
gradle.projectsEvaluated {
    assert subprojects.size() == 1000
    assert configured.size() == 1000
    assert subprojects.every { it.plugins.hasPlugin('com.android.library') }
    def edges = subprojects.sum { p -> p.configurations.implementation.dependencies.withType(ProjectDependency).size() }
    assert edges == 900
    println "GRADLESCOPE_CONFIGURED modules=${configured.size()} directEdges=${edges}"
}
tasks.register('resolveAllDebug') {
    doLast {
        def rows = []
        subprojects.sort { it.path }.each { p ->
            ['debugCompileClasspath', 'debugRuntimeClasspath'].each { name ->
                def result = p.configurations.getByName(name).incoming.resolutionResult
                def dependencies = result.allDependencies
                def unresolved = dependencies.findAll { it instanceof UnresolvedDependencyResult }
                if (!unresolved.empty) throw new GradleException("Unresolved dependencies: ${unresolved}")
                rows.add([module:p.path, configuration:name, components:result.allComponents.size(), edges:dependencies.size()])
            }
        }
        assert rows.size() == 2000
        assert rows.sum { it.edges } == 1800
        assert rows.sum { it.components } == 3800
        def report = [modules:1000, configurations:rows.size(), components:rows.sum { it.components }, edges:rows.sum { it.edges }, componentSemantics:'sum per configuration, includes each root; not globally unique', rows:rows]
        def out = file(System.getProperty('gradlescope.resolution', "${buildDir}/resolution.json"))
        out.parentFile.mkdirs(); out.text = JsonOutput.prettyPrint(JsonOutput.toJson(report))
        println "GRADLESCOPE_RESOLVED modules=1000 configurations=${rows.size()} components=${report.components} edges=${report.edges}"
    }
}
''')
    for i in range(1000):
        name = f'lib{i:04d}'
        deps = list(range(i+1, i+10)) if i % 10 == 0 else []
        write(f'modules/{name}/build.gradle', 'dependencies {\n' + ''.join(f"    implementation project(':lib{j:04d}')\n" for j in deps) + '}\n')
        refs = ' + '.join(f'org.gradlescope.lib{j:04d}.Value.value()' for j in deps) or str(i)
        write(f'modules/{name}/src/main/java/org/gradlescope/{name}/Value.java', f'package org.gradlescope.{name};\npublic final class Value {{ public static int value() {{ return {refs}; }} }}\n')
        write(f'modules/{name}/src/main/AndroidManifest.xml', '<manifest xmlns:android="http://schemas.android.com/apk/res/android"/>\n')
        write(f'modules/{name}/src/main/res/values/strings.xml', f'<resources><string name="label_{name}">{name}</string></resources>\n')
    manifest = fingerprint(root)
    write('fixture.json', json.dumps(manifest, indent=2)+'\n')
    return manifest

def fingerprint(root=ROOT):
    paths = [root/'settings.gradle', root/'build.gradle', root/'gradle.properties']
    for i in range(1000):
        p = module_path(root,i)
        paths += [p/'build.gradle', *sorted((p/'src').rglob('*'))]
    files = {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}
    digest = hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',', ':')).encode()).hexdigest()
    return dict(modules=1000, groups=100, direct_edges=900, sha256=digest, files=files)

if __name__ == '__main__':
    from locking import benchmark_lock
    with benchmark_lock(ROOT):
        print(json.dumps({k:v for k,v in generate().items() if k!='files'}))
