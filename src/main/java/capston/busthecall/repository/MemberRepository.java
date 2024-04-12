package capston.busthecall.repository;


import capston.busthecall.domain.Member;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface MemberRepository extends JpaRepository<Member, Long> {
    Optional<Member> findByName(String name);

    Optional<Member> findByNameAndDeletedFalse(String name);

    Optional<Member> findByEmailAndDeletedFalse(String email);

    Optional<Member> findByIdAndDeletedFalse(Long Id);
}
