package com.iam.repository;

import com.iam.entity.Permission;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
public interface PermissionRepository extends JpaRepository<Permission, Long> {

    Optional<Permission> findByCode(String code);

    boolean existsByCode(String code);

    List<Permission> findByCodeIn(Collection<String> codes);

    @Query("SELECT p FROM Permission p WHERE " +
           "(:keyword IS NULL OR :keyword = '' OR " +
           "LOWER(p.code) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
           "LOWER(p.name) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
           "LOWER(p.resource) LIKE LOWER(CONCAT('%', :keyword, '%')))")
    Page<Permission> searchPermissions(@Param("keyword") String keyword, Pageable pageable);
}
