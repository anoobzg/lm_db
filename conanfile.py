from conan import ConanFile
from conan.tools.cmake import CMakeDeps, CMakeToolchain

class CppTemplateProject(ConanFile):
    settings = "os", "build_type"

    def requirements(self):
        # Add your dependencies here
        self.requires("sqlite3/3.43.0")
        self.requires("openssl/1.1.1w")
        self.requires("gtest/1.15.0")

    def generate(self):
        tc = CMakeToolchain(self)
        tc.user_presets_path = False
        tc.generate()
        cd = CMakeDeps(self)
        cd.generate()
