
__add_real_target(db_read exe SOURCE db_read.cpp
                    LIB lm_db
        )

__add_real_target(db_write exe SOURCE db_write.cpp
                    LIB lm_db
        )