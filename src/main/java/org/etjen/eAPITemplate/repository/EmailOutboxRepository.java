package org.etjen.eAPITemplate.repository;

import jakarta.persistence.LockModeType;
import org.etjen.eAPITemplate.domain.model.EmailOutbox;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import java.util.List;

public interface EmailOutboxRepository extends JpaRepository<EmailOutbox, Long> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            SELECT e
              FROM EmailOutbox e
            WHERE e.status = org.etjen.eAPITemplate.domain.model.enums.MailStatus.PENDING
            ORDER BY e.createdAt ASC
            """)
    List<EmailOutbox> findBatch(PageRequest page);
}
