package com.iam.repository;

import com.iam.entity.Role;
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
public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByCode(String code);

    boolean existsByCode(String code);

    List<Role> findByCodeIn(Collection<String> codes);

    @Query("SELECT r FROM Role r WHERE " +
           "(:keyword IS NULL OR :keyword = '' OR " +
           "LOWER(r.code) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
           "LOWER(r.name) LIKE LOWER(CONCAT('%', :keyword, '%')))")
    Page<Role> searchRoles(@Param("keyword") String keyword, Pageable pageable);
}
