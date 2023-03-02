package com.C9group34.socialnetworkproject.repository;

import com.C9group34.socialnetworkproject.models.Comment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface CommentRepository extends JpaRepository<Comment, Integer> {
    @Query(
            value = "SELECT * FROM COMMENTS c WHERE c.publication_id = :publicationId",
            nativeQuery = true)
    List<Comment> retrieveAllCommentsOfAPublication(Integer publicationId);

}
