from functools import lru_cache
from importlib.resources import files

import yaml

from .models import Profile


@lru_cache(maxsize=1)
def _profiles() -> tuple[Profile, ...]:
    # Profiles ship with the package and never change during a process, so a
    # single cached parse is safe. A tuple prevents callers from mutating the
    # cached result.
    profiles = []
    for resource in files("cwe_witness").joinpath("profiles").iterdir():
        if resource.name.endswith(".yaml"):
            profile = Profile.model_validate(yaml.safe_load(resource.read_text(encoding="utf-8")))
            profiles.append(profile)
    return tuple(profiles)


def available_profiles() -> tuple[Profile, ...]:
    return _profiles()


def load_profile(reference: str) -> Profile | None:
    return next(
        (
            profile
            for profile in available_profiles()
            if reference == f"{profile.profile_id}@{profile.version}"
        ),
        None,
    )
