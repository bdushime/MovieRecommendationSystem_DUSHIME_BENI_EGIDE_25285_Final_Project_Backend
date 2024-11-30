package com.example.signup.audit;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    @Query("SELECT DATE(a.timestamp) as date, COUNT(a) as count FROM AuditLog a GROUP BY DATE(a.timestamp)")
    List<Object[]> countActionsPerDay();

}
