#include <stdlib.h>
#include <string.h>

void free_slice(char** array, int length){
    for (int i = 0; i < length; i++ )
    {
       free(array[i]);
    }
    free(array);
}

char** slice(char ** args, int argc, int index){
    int next = 0;
    char** items = malloc((argc-1) * sizeof(char*));
    for(int i = 0; i < argc; i++){
        if(i != index){
            items[next] = malloc(strlen(args[i]));
            strcpy(items[next], args[i] );
            next++;
        }
    }
    return items;
} 
