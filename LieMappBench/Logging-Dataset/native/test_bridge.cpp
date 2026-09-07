#include "bridge.h"

int main() {
    const float values[] = {0.0f, -1.0f, 0.125f, 2.5f};
    if (liemapp::enabled()) {
        liemapp::emit("bridge_test", __FILE__, __func__, __LINE__, "common.native.bridge-test",
            {{"status", "success"}, {"returncode", 0}}, "Transport round-trip fixture",
            liemapp::json::array({liemapp::tensor("values", values, 4, {2, 2})}));
    }
    return 0;
}
