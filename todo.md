

# General
- Backup should allow regex expression to mark paths that should be avoided.
- Backup should be pause-able
    - Backup should make **checkpoints**
        - Checkpoint should serialize all necessary variables (some may be loaded from the recently modified files)
        - After successfully uploading/updating/deleting any file
        - We can focus only on updates

1. Load Arrays from the downloaded manifest
    - `content_hashes` are loaded
    - *`content_hashes_stay` has everywhere `false`*
    * Checkpoint:
        - `content_hashes` can be loaded at `FILENAME_COMBINED`
2. `ScanObjects`
    - `current_target` must be saved
    - `new_content_hashes` must be saved
    - *`new_content_hashes_mapper` has everywhere `-1`*
    * **TODO**:
        - `new_content_hashes` should be saved at `FILENAME_HASHES_NEW`, or can be recalculated back again.
    * Checkpoint:
        - `current_target` can be loaded through `FILENAME_OBJECTS_TO_CORRECT`
        - `new_content_hashes` can be loaded through `FILENAME_HASHES_NEW`   
3. `CorrectObject` - Rewrites `FILENAME_OBJECTS_TO_CORRECT` to `FILENAME_OBJECTS`
    - `new_content_hashes_mapper` must be saved



1. Check Fdr
2. 




# Manifest
- File Structure:
    - File content must look completely random and not reveal type of encryption or salt.

