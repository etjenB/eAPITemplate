package org.etjen.eAPITemplate.domain.model.enums;

public enum AccountStatus {
    PENDING_VERIFICATION,   // user signed up, must verify e-mail
    ACTIVE,                 // everything OK
    SUSPENDED,              // admin or automated policy; reversible
    DELETED                 // soft-delete / part of processing for GDPR “right to be forgotten”
}

/*
*
* * Status	                |    E-mail verified?	|   May log in?	  |   Data kept?
* * PENDING_VERIFICATION    |           X           |        X        |       ✔
* * ACTIVE                  |           ✔           |        ✔        |       ✔
* * SUSPENDED               |           ✔           |        X        |       ✔
* * DELETED                 |           -           |        X        |       row kept but anonymized
*
*/