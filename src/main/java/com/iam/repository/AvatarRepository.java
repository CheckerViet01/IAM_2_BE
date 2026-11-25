package com.iam.repository;

import com.iam.entity.Avatar;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AvatarRepository extends JpaRepository<Avatar, Long> {

    List<Avatar> findByUserIdAndDeletedFalseOrderByUploadedAtDesc(Long userId);

    @Modifying
    @Query("UPDATE Avatar a SET a.current = false WHERE a.userId = :userId")
    void resetCurrentAvatars(@Param("userId") Long userId);
}
