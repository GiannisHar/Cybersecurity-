#include "FilterFunctions.h"

int main(
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPSTR lpCmdLine,
    int nCmdShow
)
{
    if (FilterLoader() == FALSE)
    {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
