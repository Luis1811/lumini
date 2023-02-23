package com.C9group34.socialnetworkproject.repository;

import com.C9group34.socialnetworkproject.models.Comment;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CommentRepository extends JpaRepository<Comment, Integer> {
}
